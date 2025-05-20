

#Seed stuff to bc
# from core.nonce_based import Blockchain

# bc = Blockchain()
# bc.add_block("Vertrauliche Nachricht #1")
# bc.add_block("Vertrauliche Nachricht #2")

# for b in bc.chain:
#     print(f"Block {b.index} | Nonce: {b.nonce} | Hash: {b.hash}")
#

# smarten Switch
# Example usage: python main.py cli or python main.py fastapi blabla...

import sys

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        from cli.guardian_cli import run_cli
        run_cli()
    elif len(sys.argv) > 1 and sys.argv[1] == "flask":
        from api.flask_app import app
        app.run()
    elif len(sys.argv) > 1 and sys.argv[1] == "fastapi":
        import uvicorn
        uvicorn.run("api.fastapi_app:app", host="0.0.0.0", port=8000)
    else:
        print("Usage: python main.py [cli|flask|fastapi]")

if __name__ == "__main__":
    main()
