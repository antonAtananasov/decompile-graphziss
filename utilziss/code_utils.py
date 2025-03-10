import os
import subprocess


class GhidraProject:
    def __init__(
        self,
        target_binary: str,
        ghidra_headless_path: str,
        ghidra_project_path: str,
        ghidra_project_name: str,
    ):
        self.target_binary_path = target_binary
        self.target_binary_name = os.path.split(self.target_binary_path)[1]
        self.ghidra_headless_path = ghidra_headless_path
        self.ghidra_project_path = ghidra_project_path
        self.ghidra_project_name = ghidra_project_name
        self.createProject()

    def prepareCommand(self, args: list[str]) -> str:
        cmd = f"{os.path.relpath(self.ghidra_headless_path)} {os.path.relpath(self.ghidra_project_path)} {os.path.relpath(self.ghidra_project_name)}"
        return " ".join([cmd] + args)

    def ghidraCommand(self, args: list[str]):
        cmd = self.prepareCommand(args)
        print("Attempting to run command:", cmd)
        process = subprocess.run(cmd, shell=True, check=True)
        return process

    def createProject(self):
        return self.ghidraCommand(["-import", self.target_binary_path])

    def ghidra_script(self, postscript: str, output_file: str):
        try:
            process = self.ghidraCommand(
                [
                    "-process",
                    self.target_binary_name,
                    "-postScript",
                    os.path.relpath(postscript),
                ]
            )
            output = ""
            with open(output_file, "r") as f:
                output = f.read()
            return output
        except:
            print("FAILED TO EXECUTE!")


def get_functions(extracted_code: str, prefix: str) -> dict[str:str]:
    extracted_functions = {}
    start = 0
    while True:
        firstIndex = extracted_code.find(prefix, start)
        if firstIndex < 0:
            break
        secondIndex = extracted_code.find(prefix, firstIndex + 1)
        if secondIndex < 0:
            break

        function_code = extracted_code[firstIndex:secondIndex].strip()
        function_name = function_code.split("\n")[0].removeprefix(prefix).strip()
        extracted_functions[function_name] = function_code

        start = secondIndex

    return extracted_functions
