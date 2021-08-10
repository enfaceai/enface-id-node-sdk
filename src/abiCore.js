export const ABICore = [
  {
    'constant': false,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_names',
        'type': 'bytes32[]',
      },
      {
        'name': '_shifts',
        'type': 'uint256[]',
      },
      {
        'name': '_mixedValues',
        'type': 'bytes',
      },
    ],
    'name': 'addAlias',
    'outputs': [],
    'payable': true,
    'stateMutability': 'payable',
    'type': 'function',
  },
  {
    'constant': false,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_indexes',
        'type': 'uint256[]',
      },
      {
        'name': '_shifts',
        'type': 'uint256[]',
      },
      {
        'name': '_mixedValues',
        'type': 'bytes',
      },
    ],
    'name': 'addRecord',
    'outputs': [],
    'payable': true,
    'stateMutability': 'payable',
    'type': 'function',
  },
  {
    'constant': false,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_names',
        'type': 'bytes32[]',
      },
      {
        'name': '_values',
        'type': 'bytes32[]',
      },
      {
        'name': '_shifts',
        'type': 'uint256[]',
      },
      {
        'name': '_mixedValues',
        'type': 'bytes',
      },
    ],
    'name': 'addRecordHashed',
    'outputs': [],
    'payable': true,
    'stateMutability': 'payable',
    'type': 'function',
  },
  {
    'constant': false,
    'inputs': [
      {
        'name': '_commissionAlias',
        'type': 'uint256',
      },
      {
        'name': '_commissionRecordHashed',
        'type': 'uint256',
      },
      {
        'name': '_commissionRecord',
        'type': 'uint256',
      },
    ],
    'name': 'changeParams',
    'outputs': [],
    'payable': false,
    'stateMutability': 'nonpayable',
    'type': 'function',
  },
  {
    'constant': false,
    'inputs': [
      {
        'name': '_receiver',
        'type': 'address',
      },
    ],
    'name': 'withdraw',
    'outputs': [],
    'payable': false,
    'stateMutability': 'nonpayable',
    'type': 'function',
  },
  {
    'inputs': [],
    'payable': false,
    'stateMutability': 'nonpayable',
    'type': 'constructor',
  },
  {
    'constant': true,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_names',
        'type': 'bytes32[]',
      },
    ],
    'name': 'getHashes',
    'outputs': [
      {
        'name': 'hashOwner',
        'type': 'address',
      },
      {
        'name': 'hashes',
        'type': 'bytes32[]',
      },
    ],
    'payable': false,
    'stateMutability': 'view',
    'type': 'function',
  },
  {
    'constant': true,
    'inputs': [],
    'name': 'getParams',
    'outputs': [
      {
        'name': 'commAlias',
        'type': 'uint256',
      },
      {
        'name': 'commRecordHashed',
        'type': 'uint256',
      },
      {
        'name': 'commRecord',
        'type': 'uint256',
      },
    ],
    'payable': false,
    'stateMutability': 'view',
    'type': 'function',
  },
  {
    'constant': true,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_indexFrom',
        'type': 'uint256',
      },
      {
        'name': '_indexTo',
        'type': 'uint256',
      },
    ],
    'name': 'getRecord',
    'outputs': [
      {
        'name': 'shifts',
        'type': 'uint256[]',
      },
      {
        'name': 'mixedResult',
        'type': 'bytes',
      },
    ],
    'payable': false,
    'stateMutability': 'view',
    'type': 'function',
  },
  {
    'constant': true,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
      {
        'name': '_names',
        'type': 'bytes32[]',
      },
    ],
    'name': 'getRecordHashed',
    'outputs': [
      {
        'name': 'hashOwner',
        'type': 'address',
      },
      {
        'name': 'shifts',
        'type': 'uint256[]',
      },
      {
        'name': 'mixedResult',
        'type': 'bytes',
      },
    ],
    'payable': false,
    'stateMutability': 'view',
    'type': 'function',
  },
  {
    'constant': true,
    'inputs': [
      {
        'name': '_aliasHash',
        'type': 'bytes32',
      },
    ],
    'name': 'getRecordsCounter',
    'outputs': [
      {
        'name': 'counter',
        'type': 'uint256',
      },
    ],
    'payable': false,
    'stateMutability': 'view',
    'type': 'function',
  },
];
