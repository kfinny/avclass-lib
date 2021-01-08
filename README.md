# avclass-lib
An attempt to convert malicia/avclass into a library for integration in other projects.

## Installation
```bash
pip install kfinny.avclass
```

### Example Usage
**NOTE: Replace '&lt;apikey&gt;' parameter with your API key to use this code example.**
```python
from vt import Client
from kfinny.avclass import Labeler
client = Client("<apikey>")
file_obj = client.get_object('/files/44d88612fea8a8f36de82e1278abb02f')
labeled_sample = Labeler().process_object(file_obj)
if labeled_sample is not None:
    print(f'{labeled_sample.sha256}: {labeled_sample.family}')
    print('Tokens in rank order:')
    print('\t' + '\n\t'.join(map(lambda x: f'{x[0]}: {x[1]}', labeled_sample.tokens)))
```

Will print
```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f: eicar
Tokens in rank order:
        eicar: 39
        testfile: 4
        string: 2
```