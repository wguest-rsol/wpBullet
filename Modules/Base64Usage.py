from core.modules import BaseClass

class Base64Usage(BaseClass):

    name = "Base64 Usage"

    severity = "Info"

    functions = [
        "base64_encode",
        "base64_decode"
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