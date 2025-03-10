import os
import time
import json
import shutil
import utilziss.ghidra_to_c as g2c
import utilziss.ghidra_to_json as g2json
from utilziss.code_utils import get_functions, GhidraProject


TARGET_BINARY_PATH = "./Tools/Easy-CrackMe-Binary-main/crackme"
GHIDRA_PATH = "./Tools/ghidra_11.2.1_PUBLIC"
GHIDRA_HEADLESS_SUFFIX = "support/analyzeHeadless"
SAVE_OUTPUTS = True

def main(target_binary:str) -> dict:
    # USER_SETTINGS

    # AUTOMATIC_SETTINGS
    TIMESTAMP = time.time()
    GHIDRA_HEADLESS_PATH = os.path.join(GHIDRA_PATH, GHIDRA_HEADLESS_SUFFIX)
    GHIDRA_PROJECT_PATH, GHIDRA_PROJECT_NAME = "./tmp", f"tmp_{TIMESTAMP}"
    GHIDRA_FULL_PROJECT_PATH = os.path.relpath(
        os.path.join(GHIDRA_PROJECT_PATH, GHIDRA_PROJECT_NAME)
    )
    DECOMPILE_POSTSCRIPT = os.path.relpath(g2c.__file__)
    JSON_POSTSCRIPT = os.path.relpath(g2json.__file__)
    DECOMPILE_C_OUTPUT_TMP_FILE = os.path.join(
        GHIDRA_PROJECT_PATH, f"{GHIDRA_PROJECT_NAME}.out.c"
    )
    GRAPH_JSON_OUTPUT_TMP_FILE = os.path.join(
        GHIDRA_PROJECT_PATH, f"{GHIDRA_PROJECT_NAME}.out.json"
    )
    DECOMPILE_OUTPUT_FN_PREFIX = f"// Function: "
    #  Edit ENV
    os.environ["DECOMPILE_OUTPUT_TIMESTAMPZISS"] = f"{TIMESTAMP}"
    os.environ["DECOMPILE_OUTPUT_NAMEZISS"] = DECOMPILE_C_OUTPUT_TMP_FILE
    os.environ["GRAPH_OUTPUT_NAMEZISS"] = GRAPH_JSON_OUTPUT_TMP_FILE
    os.environ["DECOMPILE_OUTPUT_FN_PREFIXZISS"] = DECOMPILE_OUTPUT_FN_PREFIX

    # Check settings
    for path in [
        target_binary,
        GHIDRA_PATH,
        GHIDRA_HEADLESS_PATH,
        # GHIDRA_PROJECT_PATH -> it will be automatically added
        # GHIDRA_PROJECT_NAME -> it will be automatically added
        DECOMPILE_POSTSCRIPT,
    ]:
        if not os.path.exists(path):
            print("User settings path", path, "does not exist!")
            return

    # Run commands
    ghidraProject = GhidraProject(
        target_binary,
        GHIDRA_HEADLESS_PATH,
        GHIDRA_PROJECT_PATH,
        GHIDRA_PROJECT_NAME,
    )

    extracted_json = ghidraProject.ghidra_script(
        JSON_POSTSCRIPT,
        GRAPH_JSON_OUTPUT_TMP_FILE,
    )

    extracted_blocks = json.loads(extracted_json)

    print("Extracted", len(extracted_blocks), "blocks.")

    if not SAVE_OUTPUTS:
        # Erase temporary ghidra project
        ghidraProject.deleteProject()
        temporary_paths = [
            GHIDRA_PROJECT_PATH + ".gpr",
            GHIDRA_FULL_PROJECT_PATH + ".rep",
            DECOMPILE_C_OUTPUT_TMP_FILE,
            GRAPH_JSON_OUTPUT_TMP_FILE,
        ]
        for path in temporary_paths:
            if os.path.exists(path):
                print("Removing temporary path", path)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(os.path.relpath(path))

    return extracted_blocks


if __name__ == "__main__":
    main(TARGET_BINARY_PATH)
