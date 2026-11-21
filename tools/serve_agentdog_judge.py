"""Serve a local AgentDoG 1.5 checkpoint for the AgentDojo PRE_REPLY adapter."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--port", type=int, default=18003)
    args = parser.parse_args()

    import torch
    from transformers import AutoModelForImageTextToText, AutoTokenizer

    # Use the existing CUDA-enabled PyTorch for inference and local safetensors.
    device = torch.device("cuda:0")
    tokenizer = AutoTokenizer.from_pretrained(args.checkpoint, local_files_only=True)
    model = AutoModelForImageTextToText.from_pretrained(
        args.checkpoint, local_files_only=True, use_safetensors=True, dtype=torch.bfloat16,
    ).to(device).eval()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, payload):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/models":
                self.reply(200, {"object": "list", "data": [{"id": args.model_id}]})
            else:
                self.reply(404, {"error": "Unknown route"})

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.reply(404, {"error": "Unknown route"})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4 * 1024 * 1024:
                    raise ValueError("Invalid request size")
                request = json.loads(self.rfile.read(size))
                messages = request["messages"]
                if request["model"] != args.model_id or len(messages) != 1:
                    raise ValueError("Expected one AgentDoG review prompt")
                if messages[0]["role"] != "user" or not isinstance(messages[0]["content"], str):
                    raise ValueError("Expected one AgentDoG review prompt")
                if request.get("temperature") != 0 or request.get("max_tokens") != 1024:
                    raise ValueError("Expected the AgentDoG PRE_REPLY generation settings")
            except (KeyError, TypeError, ValueError):
                self.reply(400, {"error": "Invalid AgentDoG review request"})
                return

            try:
                prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True,
                                                       enable_thinking=False)
                inputs = tokenizer([prompt], return_tensors="pt", add_special_tokens=False).to(device)
                prompt_tokens = inputs["input_ids"].shape[1]
                if prompt_tokens + 1024 > 16384:
                    self.reply(400, {"error": "AgentDoG review exceeds 16384 token budget"})
                    return
                with torch.inference_mode():
                    output = model.generate(**inputs, do_sample=False, max_new_tokens=1024)
                completion = output[0, prompt_tokens:]
                eos_ids = model.generation_config.eos_token_id
                if isinstance(eos_ids, int):
                    eos_ids = [eos_ids]
                stopped = len(completion) < 1024 or completion[-1].item() in (eos_ids or [])
                text = tokenizer.decode(completion, skip_special_tokens=True)
                self.reply(200, {"id": "agentdog-review", "object": "chat.completion", "model": args.model_id,
                                 "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                                              "finish_reason": "stop" if stopped else "length"}],
                                 "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": len(completion),
                                           "total_tokens": prompt_tokens + len(completion)}})
            except (OSError, RuntimeError, ValueError) as error:
                print(f"AgentDoG inference error: {type(error).__name__}", flush=True)
                self.reply(500, {"error": "AgentDoG inference failed"})

    with HTTPServer(("127.0.0.1", args.port), Handler) as server:
        print(f"AgentDoG ready on 127.0.0.1:{args.port}, model {args.model_id}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
