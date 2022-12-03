import base64
import sublime
import sublime_plugin
import urllib.parse
import hashlib
import html


class CryptographerBaseCommand:
    phantom_set = sublime.PhantomSet
    phantoms = list()

    @staticmethod
    def selected_regions(view):
        sels = [sel for sel in view.sel() if not sel.empty()]

        if not sels:
            sels = [sublime.Region(0, view.size())]

        return sels

    def show_exception(self, region: sublime.Region = None, msg: str = ""):
        if region is None or region.empty():
            sublime.message_dialog("[Error]: {}".format(msg))
            return
        self.highlight_error(region=region, message=msg)

    def highlight_error(self, region: sublime.Region, message: str):
        self.phantom_set = sublime.PhantomSet(self.view, "cryptographer_errors")
        self.phantoms.append(
            sublime.Phantom(
                region,
                self.create_phantom_html(message, "error"),
                sublime.LAYOUT_BELOW,
                self.navigation,
            )
        )
        self.phantom_set.update(self.phantoms)
        self.view.show(region)
        sublime.status_message("cryptographer_errors\t{}".format(message))

    @staticmethod
    def create_phantom_html(content: str, severity: str) -> str:
        stylesheet = sublime.load_resource("Packages/Cryptographer/phantom.css")
        return """<body id=inline-error>
                    <style>{}</style>
                    <div class="{}-arrow"></div>
                    <div class="{} container">
                        <div class="toolbar">
                            <a href="hide">×</a>
                        </div>
                        <div class="content">{}</div>
                    </div>
                </body>""".format(stylesheet, severity, severity, content)

    def navigation(self, href: str):
        self.clear_phantoms()

    def clear_phantoms(self):
        if isinstance(self.phantom_set, type):
            self.phantom_set = sublime.PhantomSet(self.view, "cryptographer_errors")

        self.phantoms = list()
        self.phantom_set.update(self.phantoms)


"""
Sublime Text 3 Cryptographer Hash

日本 hashes to SHA-256 as cf2abf0c5be326cb922a70f8163f91079c4d9aa8655c60ead89ad545c9de2e92

>>> view.run_command('base64_encode', {'encode_type': 'b64encode'})

"""


class CryptographerHashCommand(CryptographerBaseCommand, sublime_plugin.TextCommand):
    HASH_TYPE = {
        "MD4": "md4",
        "MD5": "md5",
        "SHA1": "sha1",
        "SHA224": "sha224",
        "SHA256": "sha256",
        "SHA384": "sha384",
        "SHA512": "sha512",
        "SHA3-224": "sha3_224",
        "SHA3-256": "sha3_256",
        "SHA3-384": "sha3_384",
        "SHA3-512": "sha3_512"
    }

    def run(self, edit, function):
        self.clear_phantoms()
        try:
            hash_algorithm = CryptographerHashCommand.HASH_TYPE[function]
        except Exception as ex:
            print(str(ex))
            self.show_exception(msg=str(ex))
            return

        print("using hash algorithm: %s" % (hash_algorithm,))

        for region in self.selected_regions(self.view):
            if not region.empty():
                original_string = self.view.substr(region)


                try:
                    hash_obj = hashlib.new(hash_algorithm)
                    hash_obj.update(original_string.encode("UTF-8"))
                    hash_string = hash_obj.hexdigest()
                except Exception as ex:
                    print(str(ex))
                    self.show_exception(region=region, msg=str(ex))
                    return

                self.view.replace(edit, region, hash_string)


"""
Sublime Text 3 Cryptographer Encode

"日本" Base64 encoded as "5pel5pys"

>>> view.run_command('cryptographer_encode', {'function': 'Base64'})

"""


class CryptographerEncodeCommand(CryptographerBaseCommand, sublime_plugin.TextCommand):

    def run(self, edit, function):
        self.clear_phantoms()
        for region in self.selected_regions(self.view):
            if not region.empty():
                original_string = self.view.substr(region)

                if function == "Base32":
                    encoded_string = base64.b32encode(original_string.encode("UTF-8")).decode("UTF-8")
                elif function == "Base64":
                    encoded_string = base64.b64encode(original_string.encode("UTF-8")).decode("UTF-8")
                elif function == "HTML":
                    encoded_string = html.escape(original_string)
                elif function == "URL":
                    encoded_string = urllib.parse.quote(original_string, safe='')
                else:
                    print("unsupported function %s" % (function,))
                    break

                self.view.replace(edit, region, encoded_string)


"""
Sublime Text 3 Cryptographer Decode

"5pel5pys" Base64 decoded as "日本"

>>> view.run_command('cryptographer_decode', {'function': 'Base64'})

"""


class CryptographerDecodeCommand(CryptographerBaseCommand, sublime_plugin.TextCommand):

    def run(self, edit, function):
        self.clear_phantoms()
        for region in self.selected_regions(self.view):
            if not region.empty():
                original_string = self.view.substr(region)

                if function == "Base32":
                    decoded_string = base64.b32decode(original_string.encode("UTF-8")).decode("UTF-8")
                elif function == "Base64":
                    decoded_string = base64.b64decode(original_string.encode("UTF-8")).decode("UTF-8")
                elif function == "HTML":
                    decoded_string = html.unescape(original_string)
                elif function == "URL":
                    decoded_string = urllib.parse.unquote(original_string)
                else:
                    print("unsupported function %s" % (function,))
                    break

                self.view.replace(edit, region, decoded_string)
