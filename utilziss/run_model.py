import os
import torch
import numpy as np
from transformers import AutoTokenizer, pipeline, CodeGenForCausalLM 


class MLHelper:
    def __init__(self):
        self.model_id = "models/Salesforce/codegen-350M-mono"

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.model = CodeGenForCausalLM.from_pretrained(self.model_id)
        self.text_classification_pipeline = pipeline(
            task="text2text-generation", model=self.model, tokenizer=self.tokenizer
        )

    def analyze_code(self, code: str | list[str]) -> dict | list[dict]:
        result= self.text_classification_pipeline(code)
        return result



if __name__ == "__main__":
    helper = MLHelper()
    codes = ["""
#include <stdio.h>
#include <string.h>

#define <mask> 100
#define <mask> 1000

int main(int argc, char *argv[]) {
  char out[S];
  char buf[N];
  char msg[] = "Welcome to the argument echoing program\n";
  int len = 0;
  buf[0] = '\0';
  printf(msg);
  while (argc) {
    sprintf(out, "argument %d is %s\n", argc-1, argv[argc-1]);
    argc--;
    strncat(buf,out,sizeof(buf)-len-1);
    len = strlen(buf);
  }
  printf("%s",buf);
  return 0;
}
            """,
            """
void safeCopy(char *dest, const char *src, size_t destSize) {
//<mask>
    strncpy(dest, src, destSize - 1);
    dest[destSize - 1] = '\0'; // Ensure null-terminated
}

"""]
    print([helper.analyze_code(code)['generated_text'] for code in codes])


