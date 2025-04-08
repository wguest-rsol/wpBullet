from core.modules import BaseClass


class Serialization(BaseClass):

    name = "Serialization"

    severity = "Info"

    functions = [
        "serialize\(",
        "unserialize\(",
        "maybe_unserialize",
        "maybe_serialize",
        "__destruct",
        "__toString",
        "__wakeup"
    ]

    blacklist = []

   # Build dynamic regex pattern to locate vulnerabilities in given content
    def build_pattern(self, content, file):

        if self.blacklist:
            blacklist_pattern = r"(?!(\s?)+(.*(" + '|'.join(self.blacklist) + ")))"
        else:
            blacklist_pattern = ""

        self.functions = [self.functions_prefix + x for x in self.functions]

        pattern = r"((" + '|'.join(self.functions) + ")\s{0,}\(?\s{0,1}" + blacklist_pattern + ".*)"
                      
        return pattern