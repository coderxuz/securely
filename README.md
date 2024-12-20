# Source code:https://github.com/coderxuz/securely
# Securely

**Securely** is a Python package that helps with authentication and authorization in FastAPI applications.

## Installation

You can install the package via `pip`:

```bash
pip install securely
```

# Quick start
```markdown
```python
from securely import Auth
from fastapi import FastAPI


from datetime import timedelta

app = FastAPI()

auth = Auth(
    secret_key="bla bla",
    access_token_expires=timedelta(days=1),
    refresh_token_expires=timedelta(days=7),
)

just_db = [{"username": "john", "password": "gdfdfgdgdrgdr"}]


@app.post("/login")
async def login(data: dict):
    new_user = {"username": data.get("username")}

    new_user["password"] = auth.hash_password(password=data.get("password"))

    just_db.append(new_user)

    tokens = auth.create_tokens(subject=new_user.get("username"))

    return tokens

```