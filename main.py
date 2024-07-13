import os
import boto3
import datetime

import subprocess
import logging
import requests

from domain_list import DomainList
from config import Config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger()

config = Config("./config.yaml")

conf_days_before_expiry = int(config.get("days_before_expiry", 10))
conf_domain_list = config.get_required("domain_list")
conf_domain_email = config.get_required("domain_email")

aws_region = config.get_required("aws_region")
boto3_session = boto3.Session(
    aws_access_key_id=config.get_required("aws_access_key_id"),
    aws_secret_access_key=config.get_required("aws_secret_access_key"),
    region_name=config.get_required("aws_region"),
)

domain_list = DomainList(conf_domain_list)


def chmod_digit(file_path, perms):
    logger.info(f"Setting permissions for {file_path} to {perms}")
    os.chmod(file_path, int(str(perms), base=8))


def send_mattermost_error_notification(message):
    webhook_url = config.get("error_notification.mattermost_webhook_url")
    send_mattermost_notification(message, webhook_url)


def send_mattermost_info_notification(message):
    webhook_url = config.get("info_notification.mattermost_webhook_url")
    send_mattermost_notification(message, webhook_url)


def send_mattermost_notification(message, webhook_url):
    if webhook_url:
        payload = {"text": message}
        try:
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send Mattermost notification: {e}")


def get_challenge():
    if config.get("cloudflare_token") is not None:
        logger.info("Cloudflare configuration detected")
        with open("/tmp/cloudflare.ini", "w") as file:
            file.write("dns_cloudflare_api_token = " + config.get("cloudflare_token"))
            chmod_digit("/tmp/cloudflare.ini", 600)

        return [
            "--dns-cloudflare",
            "--dns-cloudflare-propagation-seconds",
            "60",
            "--dns-cloudflare-credentials",
            "/tmp/cloudflare.ini",
        ]
    else:
        logger.info("Using nginx for challenge")
        return ["--nginx"]


def read_and_delete_file(path):
    logger.info(f"Reading and deleting file: {path}")
    with open(path, "r") as file:
        contents = file.read()
    os.remove(path)
    return contents


def provision_cert(email, lineage, domains):
    logger.info(f"Attempting to provision cert for: ({lineage}) {domains}")
    domain_args = []
    for domain in domains:
        domain_args.extend(["-d", domain])

    params = [
        "certbot",
        "certonly",
        "-n",  # non-interactive
        "--agree-tos",
        "--email",
        email,
        "--config-dir",
        "/tmp/config-dir/",
        "--work-dir",
        "/tmp/work-dir/",
        "--logs-dir",
        "/tmp/logs-dir/",
    ] + domain_args
    params += get_challenge()

    logger.info(f"Executing command: {' '.join(params)}")

    subp = subprocess.run(params, capture_output=True)
    if subp.returncode!= 0:
        raise Exception(subp.stderr.decode("utf-8").replace("\\n", "\n"))
    
    stdout_output = subp.stdout.decode('utf-8').replace("\\n", "\n")
    logger.info(f"Certbot command executed successfully with result: {stdout_output}")

    path = "/tmp/config-dir/live/" + lineage + "/"
    return {
        "certificate": read_and_delete_file(path + "cert.pem"),
        "private_key": read_and_delete_file(path + "privkey.pem"),
        "certificate_chain": read_and_delete_file(path + "chain.pem"),
    }


def should_provision(domains):
    logger.info(f"Checking if provisioning is needed for domains: {domains}")
    existing_cert = find_existing_cert(domains)
    if existing_cert:
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = existing_cert["Certificate"]["NotAfter"]
        expiry = (not_after - now).days
        cutoff = conf_days_before_expiry
        message = f"Existing cert found for {', '.join(domains)} in ACM region {aws_region} with expiry ({expiry}) <= cutoff ({cutoff}), no need to renew"
        logger.info(message)
        send_mattermost_info_notification(message)
        return expiry <= cutoff
    else:
        logger.info("No existing cert found, provisioning new one")
        return True


def find_existing_cert(domains):
    logger.info(f"Finding existing cert in region {aws_region} for domains: {domains}")
    domains = frozenset(domains)
    client = boto3_session.client("acm")
    certs = client.list_certificates(
        Includes={
            "keyTypes": [
                "RSA_1024",
                "RSA_2048",
                "RSA_3072",
                "RSA_4096",
                "EC_prime256v1",
                "EC_secp384r1",
                "EC_secp521r1",
            ]
        },
        MaxItems=1000,
    )

    for cert in certs["CertificateSummaryList"]:
        cert = client.describe_certificate(CertificateArn=cert["CertificateArn"])
        sans = frozenset(cert["Certificate"]["SubjectAlternativeNames"])
        if sans.issubset(domains):
            logger.info(f"Matching cert found: {cert['Certificate']['CertificateArn']}")
            return cert

    logger.info(f"No matching cert found in region {aws_region}")
    return None


def upload_cert_to_acm(cert, domains):
    logger.info(f"Uploading cert to ACM for domains: {domains}")
    existing_cert = find_existing_cert(domains)
    client = boto3_session.client("acm")

    if existing_cert:
        certificate_arn = existing_cert["Certificate"]["CertificateArn"]
        logger.info(f"Updating existing cert: {certificate_arn}")
        acm_response = client.import_certificate(
            CertificateArn=certificate_arn,
            Certificate=cert["certificate"],
            PrivateKey=cert["private_key"],
            CertificateChain=cert["certificate_chain"],
        )
    else:
        logger.info("Importing new cert")
        acm_response = client.import_certificate(
            Certificate=cert["certificate"],
            PrivateKey=cert["private_key"],
            CertificateChain=cert["certificate_chain"],
        )

    message = f"Provisioned certificate uploaded for {', '.join(domains)} in ACM region {aws_region} with ARN {acm_response['CertificateArn']}"
    logger.info(message)
    send_mattermost_info_notification(message)

    return True


def process_lineage(lineage, domains, email):
    try:
        logger.info(f"Processing: ({lineage}) {domains}")
        if should_provision(domains):
            cert = provision_cert(email, lineage, domains)
            upload_cert_to_acm(cert, domains)
    except Exception as e:
        error_message = e

        if hasattr(e, "output") and e.output is not None and len(e.output):
            error_message = e.output
        elif hasattr(e, "message") and e.message is not None and len(e.message):
            error_message = e.message

        error_message = (
            f"Error processing lineage ({lineage}) {domains}: {error_message}"
        )
        logger.error(error_message)
        send_mattermost_error_notification(error_message)


logger.info(f"Processing domain list: {domain_list.original}")
for lineage, domains in domain_list.lineage.items():
    process_lineage(lineage, domains, conf_domain_email)
