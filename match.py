import logging
import re

log = logging.getLogger(__name__)

class ForwardMatch(object):
    def find(self, host, port, proto="tcp"):
        raise NotImplementedError
    
class SocksForwardRegexMatch(ForwardMatch):
    def __init__(self, rules):
        self.rules = rules
        
    def find(self, host, port, proto="tcp"):
        for (pattern, forward) in self.rules.iteritems():
            (h, p, pr) = pattern
            if re.match(pr, proto) and re.match(h, host.rstrip(".")) \
                        and re.match(p, str(port)):
                log.info("forward rule %s found for %s:%d:%s" % (forward, host, port, proto))
                return forward
        return None
    