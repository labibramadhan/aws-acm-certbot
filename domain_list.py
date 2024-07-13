class DomainList:
    def __init__(self, domains):
        self.original = domains
        self.lineage = self.parse(domains)

    def parse(self, domains):
        result = {}
        for domain in domains:
            lineage = self.choose_lineagename(domain.strip())
            if lineage in result:
                result[lineage].append(domain.strip())
            else:
                result[lineage] = [domain.strip()]
        return result

    def is_wildcard_domain(self, domain):
        wildcard_marker: Union[Text, bytes] = b"*."
        if isinstance(domain, str):
            wildcard_marker = u"*."
        return domain.startswith(wildcard_marker)

    def choose_lineagename(self, domain):
        if self.is_wildcard_domain(domain):
            return domain[2:]
        return domain

    def to_string(self):
        return '({0})'.format(self.original)