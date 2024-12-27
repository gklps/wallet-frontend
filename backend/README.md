# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
```
go run wallet.go

```

### Curl request to login
```
curl -X POST http://localhost:8080/login -d '{"email":"riya@gmail.com","password":"123"}'
``` 

### Curl request to view profile
```
curl -L -X GET 'http://localhost:8080/profile' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' 
```

### Curl request to create a wallet
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":<rubix node port number in int>}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":20009}'
```
**Response:**
```
{"did":"bafybmie5l4jpfxmnnqi3sk4vnt6fx3sbuzf632ubeflc7let6rljzq4usi"}
```
#### sample with invalid request (invalid port)
```
curl -X POST http://localhost:8080/create_wallet -d '{"port":20001}'
```
**Response:**
```
{"error":"Failed to request DID"}
```


### Curl request to register did
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq"}'
```
**Response:**
```
"DID registered successfully"
```
#### sample with invalid request (invalid did)
```
curl -L -X POST http://localhost:8080/register_did -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2fgh"}'
```
**Response:**
```
{"error":"DID mismatch"}
```


### Curl request to setup quorum 
```
curl -L -X POST http://localhost:8080/setup_quorum -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -L -X POST 'http://localhost:8080/setup_quorum' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq"}'
```
**Response:**
```
"Quorum setup done successfully"
```
#### sample with invalid request (invalid did)
```
curl -L -X POST 'http://localhost:8080/setup_quorum' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttajhg"}'
```
**Response:**
```
{"error":"DID mismatch"}
```


### Curl request to add peer info 
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"self_did":"<user did>", "DID":"<peer did>", "DIDType":<0 to 4>, "PeerID":"<peer ID>"}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"self_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq", "DID":"bafybmia3zyr73srf5jnm3xuvuetepn5alh53wbtw6ep4pnojey6emtwcmu", "DIDType":4, "PeerID":"12D3KooWRimkVSDAcwESk7HtKTtYaUmzpVrnfidkNKL5HyWVRpTL"}'
```
**Response:**
```
"Peers added successfully"
```
#### sample with invalid request (invalid peerId)
```
curl -L -X POST http://localhost:8080/add_peer -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"self_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq", "DID":"bafybmia3zyr73srf5jnm3xuvuetepn5alh53wbtw6ep4pnojey6emtwcjh", "DIDType":4, "PeerID":""}'
```
**Response:**
```
{"error":"test token generation failed, Invalid Peer ID"}
```

### Curl request to generate test RBT
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "number_of_tokens":<amount in int>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' -d '{"did":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq", "number_of_tokens":10}'
```
**Response:**
```
"Test tokens generated successfully"
```
#### sample with invalid request (invalid input format to number_of_tokens)
```
curl -L -X POST http://localhost:8080/testrbt/create -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq", "number_of_tokens":1.0}'
```
**Response:**
```
{"error":"Invalid input"}
```


### Curl request to get balance
```
curl -L -X GET "http://localhost:8080/request_balance?did=<user DID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/request_balance?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"account_info":[{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","did_type":0,"locked_rbt":0,"pinned_rbt":0,"pledged_rbt":0,"rbt_amount":9.6}],"message":"Got account info successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to did)
```
curl -L -X GET "http://localhost:8080/request_balance?did=" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI'
```
**Response:**
```
{"error":"Missing required parameter: did"}
```


### Curl request to unpledge pledged RBTs
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<user DID>"}'

```
#### sample with valid request (pending)
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NTAzNTQsInN1YiI6ImJhZnlibWlnZnE3ZG5ocWRwZ2hsdXFmaXJ2bjV5ejc2dnB2cmt1dG9mc3dpaDdzaWRtcW1zc29odmJxIn0.nmgjyGxALW-ecfmBiZMaBEWhdx4P_qLkiE-y9Zgy6Tc' -d '{"did":"bafybmigfq7dnhqdpghluqfirvn5yz76vpvrkutofswih7sidmqmssohvbq"}'
```
**Response:**
```
"Unpledging of pledged tokens was successful, Total Unpledge Amount: 2.4400000000000004 RBT"
```
#### sample with invalid request (invalid did)
```
curl -L -X POST http://localhost:8080/rbt/unpledge -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU0NjY4MjIsInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.NeIFZ0BitoO5hEaMF_fZbyyCGD2b4jh9FVM4536VMFI' -d '{"did":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3byhj"}'
```
**Response:**
```
{"error":"DID mismatch"}
```


### Curl request to sign
```
curl -X POST http://localhost:8080/sign -d '{"did":"<rubix node DID>","data":"<signing data>"}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/sign -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","data":"txn_data"}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","signature":"3046022100b28b4bc6de55f419f9e2f887198cb6fd5d50fd59bb90a19fb40b5865ee542b71022100a09201751c45517d1063d2616ef29ec27b94f548c384aa2cb7850de76c69f55c","signedData":"txn_data"}
```
#### sample with invalid request (invalid did)
```
curl -X POST http://localhost:8080/sign -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk287h","data":"txn_data"}'
```
**Response:**
```
{"error":"User not found"}
```


### Curl request to transfer RBTs
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<sender DID>","receiver":"<receiver DID>", "rbt_amount":<transaction amount in float>}'
```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","receiver":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq", "rbt_amount":2.56}'
```
**Response:**
```
{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pZmVicWx2cTJ1ZXR4bzNtZ3J3dWdmM2s0cmRqdXBvNmg2ZmtuN216cmI1ZWtoeHR0YW1ucSIsImV4cCI6MTczNTM2OTc3NywiaWF0IjoxNzM1MjgzMzc3LCJyYnRfYW1vdW50IjoyLjU2LCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYjN0dnFsbmIyNXVocGR3djJ5NHdiaHR0em1wd2RlbDNuYmxmb3UzdnU0dnp2N2IzYnlicSJ9.Bd3mdXLnsWeQlrSasAWfNjgmvqAls1MScTYMsMLVgHw","status":"Transfer finished successfully in 3.85767431s with trnxid d881d09212ef568009a81d37abf9506bf52e7990790bd6bf47c4113a6777abcc"}
```
#### sample with invalid request (invalid rbt_amount)
```
curl -L -X POST http://localhost:8080/request_txn -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","receiver":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq", "rbt_amount":2.56087}'
```
**Response:**
```
{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pZmVicWx2cTJ1ZXR4bzNtZ3J3dWdmM2s0cmRqdXBvNmg2ZmtuN216cmI1ZWtoeHR0YW1ucSIsImV4cCI6MTczNTM2OTg2NCwiaWF0IjoxNzM1MjgzNDY0LCJyYnRfYW1vdW50IjoyLjU2MDg3LCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYjN0dnFsbmIyNXVocGR3djJ5NHdiaHR0em1wd2RlbDNuYmxmb3UzdnU0dnp2N2IzYnlicSJ9.vxp0zGG-9jBFSDvLPz3Fv2JvJjAnsu27OxEEuMDTUEg","status":"transaction amount exceeds 3 decimal places"}
```


### Curl request to get all transactions by DID
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=<user DID>&role=<Sender/Receiver>&StartDate=<start of the date range>&EndDate=<end of the date range>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
**Note** : either provide role of the did or else date range to filter the Txns list

#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&role=sender" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"TxnDetails":[{"Amount":2.56,"BlockID":"1-20eeb4d491c1672295d364863bcda1c8f5fa3a589a35deea5ea8a28f78610c9b","Comment":"","DateTime":"2024-12-18T22:56:27.061097073+05:30","DeployerDID":"","Epoch":1734542783,"Mode":0,"ReceiverDID":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq","SenderDID":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","Status":true,"TotalTime":3827,"TransactionID":"8b8c1874d6dedca90d141464b51da089e1d0d82904a5e893aa155ca2746f20d0","TransactionType":"02"},{"Amount":2.56,"BlockID":"1-a7f2ab4ada088bedffc90aaabba14b22a52819a1991da7ac5cf9e034be018625","Comment":"","DateTime":"2024-12-27T12:39:41.362751158+05:30","DeployerDID":"","Epoch":1735283377,"Mode":0,"ReceiverDID":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq","SenderDID":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","Status":true,"TotalTime":3857,"TransactionID":"d881d09212ef568009a81d37abf9506bf52e7990790bd6bf47c4113a6777abcc","TransactionType":"02"}],"message":"Retrieved Txn Details","result":"Successful","status":true}
```
#### sample with invalid request (invalid did)
```
curl -L -X GET "http://localhost:8080/txn/by_did?did=bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dft&role=sender" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"error":"DID mismatch"}
```

### Curl request to create FT
```
curl -L -X POST "http://localhost:8080/create_ft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "token_count":<number of RBTs in int>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/create_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "ft_name":"test1",
    "ft_count":10,
    "token_count":20
}'
```
**Response:**
```
"FT created successfully"
```
#### sample with invalid request (invalid input format to token_count)
```
curl -L -X POST http://localhost:8080/create_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "ft_name":"test2",
    "ft_count":10,
    "token_count":0.3
}'
```
**Response:**
```
{"error":"Invalid input"}
```

### Curl request to transfer FT
```
curl -L -X POST "http://localhost:8080/transfer_ft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"sender":"<sender DID>", "receiver":<receiver DID>, "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "creatorDID":<DID of FT creator>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/transfer_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "sender":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "receiver":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq",
    "creatorDID":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "ft_name":"test1",
    "ft_count":2, 
    "quorum_type":2
}'
```
**Response:**
```
"FT Transfer finished successfully in 2.655295048s with trnxid 541616722e6d2d005d503de53ccc0e888a673de79697005e9bf90198f1bfac6d"
```
#### sample with invalid request (invalid input format to ft_count)
```
curl -L -X POST http://localhost:8080/transfer_ft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "sender":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "receiver":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq",
    "creatorDID":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "ft_name":"test1",
    "ft_count":2.7, 
    "quorum_type":2
}'
```
**Response:**
```
{"error":"Invalid input"}
```

### Curl request to get all FTs' info
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=<user DID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' 
```
**Response:**
```
{"ft_info":[{"creator_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","ft_count":2,"ft_name":"test1"}],"message":"Got FT info successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to did)
```
curl -L -X GET "http://localhost:8080/get_all_ft?did=" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' 
```
**Response:**
```
{"error":"Missing required parameter: did"}
```

### Curl request to get FT chain
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=<user DID>&tokenID=<FT token ID>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&tokenID=QmbYuoWwTeW1WxM1WbZ53PGCVg5GLTQoqpuZzQ2LirxBN5" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"TokenChainData":[{"TCBlockHashKey":"15018823c0d5b8a9a37dfb867c0f9ac32724dad8ef163c4fad9f3fc4c9af9482","TCChildTokensKey":[],"TCGenesisBlockKey":{"GBInfoKey":{"QmbYuoWwTeW1WxM1WbZ53PGCVg5GLTQoqpuZzQ2LirxBN5":{"GICommitedTokensKey":{},"GIParentIDKey":"QmRzrio1rexNo28BP66kbfqsNu9GcN9yTBFmzG5weLSduk,QmbiFvLnb328d7xbjJTgTPFvUSyAnk2gKD9pTH76mHRbgB,QmQZfVkMkBz5ccTiTJySxNanAkh8MdfcKP7m4cnuDKzYSD,QmSs9nDgT9tc52Zuto57gbHqhYexT2hWyCTFCRpWUQ2V9X,QmSxeigeWrgz8BnS7GaZtHabi2eLnyStabKqycqD2YyLWu,QmeutGzLeHqYNn1RuuDPcN9VzaoQw7SXkAYkNLs7TjQ9Wu,QmZ41UGzmvaGWofKxXiC1TegLzwjzpdRgqTATjYxQAejfD,QmYDC7QDhn8njpcwcLxmAj2kAVMBTxA2oep4MTyEemo4Qn,QmY9aBhDd1SdTEAoYuxUYUTHYN85w2JwDe9DN7MUpP2hsj,QmfC56fsRvZNFq77dQo2GDxPaAeCKBFZRzQPUe8iE1y2WU,QmdV8zr3h1xvLfmS3vkwrnripaPZZaHmGT5xxdDbVxqrmP,QmTpsNvJbGNUmBmGKA2Msq8chSTWMotkkygrEWuumNTwLX,QmfWJr92RX2gFzURVrnC7aNsoZ9EemzZQnzRYTDgBHS7qq,QmeSRrAQz1kwdcuakQd4kqy6DriuyLQzQQkkGFqysx1VXp,QmVTEHtvuao3qUwByUq9xxhtKqiJCuzoSMtu5zwSUGAB8H,QmabGK4aLcJRdFtxWUfPXKZLBsDyD7qd63yJ2jnqirLqAM,QmZCJ18o47fjQSUYv2szw9UggiKA4rNvdKBU7BsovbxBbF,QmeaaFGNboc8o35qs97RskimQcg1Rgr7qEUP5hZhobHAHZ,QmWyrYXWT4tPw8mFDvq6BXhEJAU1zsK8Q43sarKw7FezhS,QmVWasLh6XkV9vAVoDu9c2VnPoajdbr4EYvq7mhVEoNXQw","GITokenLevelKey":0,"GITokenNumberKey":8}},"GBTypeKey":""},"TCSignatureKey":{"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq":"30440220522ef06cf088dcb00f60a647cf37580f30e7e544e6d8bf0b978a20459ba4e9f6022066847083ab1e44f82d811919ab7d1c1c20f406d7be46955efb2b6d29192e8ba6"},"TCTokenOwnerKey":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","TCTokenValueKey":2,"TCTransInfoKey":{"TICommentKey":"FT generated at : 2024-12-27 12:45:20.791553358 +0530 IST m=+3096.910633743 for FT Name : test1","TITokensKey":{"QmbYuoWwTeW1WxM1WbZ53PGCVg5GLTQoqpuZzQ2LirxBN5":{"TTBlockNumberKey":"0","TTPreviousBlockIDKey":"","TTTokenTypeKey":10}}},"TCTransTypeKey":"05"}],"message":"FT tokenchain data fetched successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to tokenID)
```
curl -L -X GET "http://localhost:8080/get_ft_chain?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&tokenID="  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"error":"Missing required parameter: tokenID"}
```

### Curl request to create NFT
```
curl -L -X POST "http://localhost:8080/create_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "metadata":<metadata file path>, "artifact":"<artifact file path>"}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/create_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/NFT/test2.png"
}'
```
**Response:**
```
"NFT Token generated successfully"
```
#### sample with invalid request (invalid input path to artifact)
```
curl -L -X POST http://localhost:8080/create_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/test2.png"
}'
```
**Response:**
```
{"error":"open /home/maneesha/Rubix-Git/test2.png: no such file or directory"}
```

### Curl request to subscribe NFT
```
curl -L -X POST "http://localhost:8080/subscribe_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "nft":<nft token ID>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/subscribe_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' -d '{
    "did":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq",
    "nft":"Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA"
}'
```
**Response:**
```
"NFT subscribed successfully"
```
#### sample with invalid request (invalid input to did)
```
curl -L -X POST http://localhost:8080/subscribe_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1Mzk2NzYsInN1YiI6ImJhZnlibWliM3R2cWxuYjI1dWhwZHd2Mnk0d2JodHR6bXB3ZGVsM25ibGZvdTN2dTR2enY3YjNieWJxIn0.eMTEEtErNj4I7_MfO-0PiP2djnVz1rMZtAkCF3Hpbs8' -d '{
    "did":"",
    "nft":"Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA"
}'
```
**Response:**
```
{"error":"DID mismatch"}
```

### Curl request to deploy NFT
```
curl -L -X POST "http://localhost:8080/deploy_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{"did":"<rubix node DID>", "nft":"<nft ID>", "quorum_type":<1 or 2>}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/deploy_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "nft":"Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA",
    "quorum_type":2
}'
```
**Response:**
```
"NFT Deployed successfully in 2.315930416s"
```
#### sample with invalid request (invalid input to quorum_type)
```
curl -L -X POST http://localhost:8080/deploy_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "nft":"Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA",
    "quorum_type":4
}'
```
**Response:**
```
{"error":"test token generation failed, Invalid quorum type"}
```

### Curl request to execute NFT
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer <jwt token returned while logging in>' -d '{
  "comment": "string",
  "nft": "string",
  "nft_data": "string",
  "nft_value": 0.0,
  "owner": "string",
  "quorum_type": 0,
  "receiver": "string"
}'

```
#### sample with valid request 
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
  "comment": "nft transfer from wallet",
  "nft": "Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA",
  "nft_data": "",
  "nft_value": 11.0,
  "owner": "bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
  "quorum_type": 2,
  "receiver": "bafybmibuj72pm5x6yjhmfgacfusbk5veur5poqfm7qibk45kk5ktiep3d4"
}'
```
**Response:**
```
"NFT Executed successfully in 2.281952715s"
```
#### sample with invalid request (invalid owner)
```
curl -L -X POST http://localhost:8080/execute_nft -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0' -d '{
  "comment": "nft transfer from wallet",
  "nft": "Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA",
  "nft_data": "",
  "nft_value": 11.0,
  "owner": "bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
  "quorum_type": 2,
  "receiver": "bafybmibuj72pm5x6yjhmfgacfusbk5veur5poqfm7qibk45kk5ktiep3d4"
}'
```
**Response:**
```
{"error":"test token generation failed, no records found"}
```

### Curl request to fetch NFT
```
curl -L -X GET "http://localhost:8080/get_nft?did=<string>&nft=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'
```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&nft=Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"message":"NFT fetched successfully","result":null,"status":true}
```
#### sample with invalid request (invalid did)
```
curl -L -X GET "http://localhost:8080/get_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamhj&nft=Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9echy" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"error":"DID mismatch"}
```

### Curl request to get NFT chain
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=<string>&nft=<string>&latest=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&nft=Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9ecDA" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"NFTDataReply":[{"BlockId":"0-82227efb89892902326ccdda6422cd8a2247c037749fff6a5c181deaf6602936","BlockNo":0,"NFTData":"","NFTOwner":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","NFTValue":0},{"BlockId":"1-98baffa792c3bf87759ee19608c23f8c6afeb471f59f0a7911a971959ab7b81b","BlockNo":1,"NFTData":"","NFTOwner":"bafybmibuj72pm5x6yjhmfgacfusbk5veur5poqfm7qibk45kk5ktiep3d4","NFTValue":11}],"message":"Fetched NFT data","result":null,"status":true}
```
#### sample with invalid request (invalid input to nft)
```
curl -L -X GET "http://localhost:8080/get_nft_chain?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&nft=Qme4NFXJ7f3f4umwbjL7A6ps2udw8WdcCz5cYWG2w9echj" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"NFTDataReply":null,"message":"Failed to get nft data, token does not exist","result":null,"status":false}
```

### Curl request to get all NFTs
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=<string>" -H 'Authorization: Bearer <jwt token returned while logging in>'

```
#### sample with valid request 
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"message":"Got All NFTs","nfts":[{"nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY","nft_value":0,"owner_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq"}],"result":null,"status":true}
```
#### sample with invalid request (invalid input to did)
```
curl -L -X GET "http://localhost:8080/get_all_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttaghh" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU1NDIzMjksInN1YiI6ImJhZnlibWlmZWJxbHZxMnVldHhvM21ncnd1Z2YzazRyZGp1cG82aDZma243bXpyYjVla2h4dHRhbW5xIn0.Kii2kW5CTkdV7IjNjkaYiXTP40rYXlj7UcUWxmSxfm0'
```
**Response:**
```
{"error":"DID mismatch"}
```
