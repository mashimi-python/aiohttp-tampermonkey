# aiohttp-tampermonkey

This is our patch for aiohttp that allows it to use Tampermonkey's GM.xmlHttpRequest from inside Pyodide.


## Usage

```python
import aiohttp_tampermonkey

aiohttp_tampermonkey.monkeypatch()

import aiohttp

async with aiohttp.ClientSession() as session:
    ...
```
