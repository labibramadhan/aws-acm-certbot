class DomainList:
    def __init__(self, domains):
        self.original = domains
        self.parsed = self.parse(domains)

    def parse(self, domains):
        result = {}
        for item in domains:
            domain = item['domain']
            resolver = item['resolver']
            result.setdefault(resolver, {})
            lineage = self.choose_lineagename(domain.strip())
            result.get(resolver).setdefault(lineage, [])
            result.get(resolver).get(lineage).append(domain.strip())
        return result

    def is_wildcard_domain(self, domain):
        wildcard_marker = b"*."
        if isinstance(domain, str):
            wildcard_marker = u"*."
        return domain.startswith(wildcard_marker)

    def choose_lineagename(self, domain):
        if self.is_wildcard_domain(domain):
            return domain[2:]
        return domain

    def to_string(self):
        return '({0})'.format(self.original)