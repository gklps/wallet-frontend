# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
```
go run wallet.go

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
curl -X POST http://localhost:8080/register_did -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/register_did -d '{"did":"bafybmigfq7dnhqdpghluqfirvn5yz76vpvrkutofswih7sidmqmssohvbq"}'
```
**Response:**
```
"DID registered successfully"
```
#### sample with invalid request (invalid port)
```
curl -X POST http://localhost:8080/register_did -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2fgh"}'
```
**Response:**
```
{"error":"User not found"}
```


### Curl request to setup quorum 
```
curl -X POST http://localhost:8080/setup_quorum -d '{"did":"<user DID>"}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/setup_quorum -d '{"did":"bafybmieksq2loys6qpszqju33omatw4prgic6kwnpxkklkl2zeslog4g34"}'
```
**Response:**
```
"Quorum setup done successfully"
```
#### sample with invalid request (invalid port)
```
curl -X POST http://localhost:8080/setup_quorum -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2fgh"}'
```
**Response:**
```
{"error":"User not found"}
```


### Curl request to add peer info 
```
curl -X POST http://localhost:8080/add_peer -d '{"self_did":"<user did>", "DID":"<peer did>", "DIDType":<0 to 4>, "PeerID":"<peer ID>"}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/add_peer -d '{"self_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq", "DID":"bafybmia3zyr73srf5jnm3xuvuetepn5alh53wbtw6ep4pnojey6emtwcmu", "DIDType":4, "PeerID":"12D3KooWRimkVSDAcwESk7HtKTtYaUmzpVrnfidkNKL5HyWVRpTL"}'
```
**Response:**
```
"Peers added successfully"
```
#### sample with invalid request (invalid did)
```
curl -X POST http://localhost:8080/add_peer -d '{"self_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq", "DID":"bafybmia3zyr73srf5jnm3xuvuetepn5alh53wbtw6ep4pnojey6emtwcmu", "DIDType":4, "PeerID":""}'
```
**Response:**
```
{"error":"test token generation failed, Invalid Peer ID"}
```

### Curl request to generate test RBT
```
curl -X POST http://localhost:8080/testrbt/create -d '{"did":"<rubix node DID>", "number_of_tokens":<amount in int>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/testrbt/create -d '{"did":"bafybmieksq2loys6qpszqju33omatw4prgic6kwnpxkklkl2zeslog4g34", "number_of_tokens":10}'
```
**Response:**
```
"Test tokens generated successfully"
```
#### sample with invalid request (invalid input format to number_of_tokens)
```
curl -X POST http://localhost:8080/testrbt/create -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq", "number_of_tokens":1.0}'
```
**Response:**
```
{"error":"Invalid input"}
```


### Curl request to get balance
```
curl -X GET "http://localhost:8080/request_balance?did=<user DID>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/request_balance?did=bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq"
```
**Response:**
```
{"account_info":[{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","did_type":0,"locked_rbt":0,"pinned_rbt":0,"pledged_rbt":0,"rbt_amount":9.6}],"message":"Got account info successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to did)
```
curl -X GET "http://localhost:8080/request_balance?did="
```
**Response:**
```
{"error":"Missing required parameters: port or did"}
```


### Curl request to unpledge pledged RBTs
```
curl -X POST http://localhost:8080/rbt/unpledge -d '{"did":"<user DID>"}'

```
#### sample with valid request (pending)
```
curl -X POST http://localhost:8080/rbt/unpledge -d '{"did":"bafybmig4x5q3ym4z7e53pgdvjfxdqvwsgidfy3yuezdwiqwbbdheqvp6qy"}'
```
**Response:**
```
"Unpledging of pledged tokens was successful, Total Unpledge Amount: 2.4400000000000004 RBT"
```
#### sample with invalid request (invalid did)
```
curl -X POST http://localhost:8080/rbt/unpledge -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2fgh"}'
```
**Response:**
```
{"error":"User not found"}
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
curl -X POST http://localhost:8080/request_txn -d '{"did":"<sender DID>","receiver":"<receiver DID>", "rbt_amount":<transaction amount in float>}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8080/request_txn -d '{"did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq","receiver":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq", "rbt_amount":2.56}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pYzZvbGtzdnh1Y3FyeGZid3FwdHlzaHU1dGFocHJhd2huaXBlbWloajdvcGZjY3BrMmRicSIsImV4cCI6MTczMzkwOTUwMCwiaWF0IjoxNzMzODIzMTAwLCJyYnRfYW1vdW50IjoxLCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYW8yZnlsenVwcHNyN2I3Y2VwbTMyZWdkNDY1dWhwbzNra3diaG5la3ZlNnUyYmVkd2IzbSJ9.srczpeBhwPK9CNa8jy6fLiUtbD0w8gFgBzlkmNRCL0M","status":"Transfer finished successfully in 2.406044531s with trnxid 828face14520df1a64d0760051afa32d8ef0036a95c00d7c9e0501f3ed9b6285"}
```
#### sample with invalid request (invalid rbt_amount)
```
curl -X POST http://localhost:8080/request_txn -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","receiver":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m", "rbt_amount":1.07655}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pYzZvbGtzdnh1Y3FyeGZid3FwdHlzaHU1dGFocHJhd2huaXBlbWloajdvcGZjY3BrMmRicSIsImV4cCI6MTczMzkwOTU4OSwiaWF0IjoxNzMzODIzMTg5LCJyYnRfYW1vdW50IjoxLjA3NjU1LCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYW8yZnlsenVwcHNyN2I3Y2VwbTMyZWdkNDY1dWhwbzNra3diaG5la3ZlNnUyYmVkd2IzbSJ9.Cqw_2pR2s27YeG1VVn0L4Oh8Hc4IsWsCOoNA8R4c4aE","status":"transaction amount exceeds 3 decimal places"}
```


### Curl request to get all transactions by DID
```
curl -X GET "http://localhost:8080/txn/by_did?did=<user DID>&role=<Sender/Receiver>&StartDate=<start of the date range>&EndDate=<end of the date range>"

```
**Note** : either provide role of the did or else date range to filter the Txns list

#### sample with valid request 
```
curl -X GET "http://localhost:8080/txn/by_did?did=bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m&role=sender"
```
**Response:**
```
{"TxnDetails":[{"Amount":1,"BlockID":"1-bf67e28f41df5d8bc06e7753a498adef98e79aafae9b23cde6f80960bc39d84c","Comment":"","DateTime":"2024-12-10T11:00:36.290045784+05:30","DeployerDID":"","Epoch":1733808632,"Mode":0,"ReceiverDID":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m","SenderDID":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","Status":true,"TotalTime":3507,"TransactionID":"2df77ca20e0fc5ebf9cd6dea1e18679113a67a5874805d6a89ac239c004157ad","TransactionType":"02"},{"Amount":1.4,"BlockID":"1-f6856fafc6b1ed156cc0006470f5d54614f8cc547b1606f4a3a90bc9132976fd","Comment":"","DateTime":"2024-12-10T11:02:57.115731527+05:30","DeployerDID":"","Epoch":1733808774,"Mode":0,"ReceiverDID":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m","SenderDID":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","Status":true,"TotalTime":2805,"TransactionID":"7d8f02a3aff5b9c411bbf3a696ff3067581797f1d43a66a09d0c684760ace7fe","TransactionType":"02"}],"message":"Retrieved Txn Details","result":"Successful","status":true}
```
#### sample with invalid request (invalid did)
```
curl -X GET "http://localhost:8080/txn/by_did?did=bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dft&role=sender"
```
**Response:**
```
{"error":"User not found"}
```

### Curl request to create FT
```
curl -X POST "http://localhost:8080/create_ft -d '{"did":"<rubix node DID>", "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "token_count":<number of RBTs in int>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/create_ft -d '{
    "did":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m",
    "ft_name":"test1",
    "ft_count":10,
    "token_count":1
}'
```
**Response:**
```
"FT created successfully"
```
#### sample with invalid request (invalid input format to token_count)
```
curl -X POST http://localhost:8080/create_ft -d '{
    "did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq",
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
curl -X POST "http://localhost:8080/transfer_ft -d '{"sender":"<sender DID>", "receiver":<receiver DID>, "ft_count":<number of FTs in int>, "ft_name":"<ft name>", "creatorDID":<DID of FT creator>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/transfer_ft -d '{
    "sender":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m",
    "receiver":"bafybmihtljjkvayu7iwjxzd4sfufywakdd3zymrgcnw7jnc3p6oltjzofe",
    "creatorDID":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m",
    "ft_name":"test1",
    "ft_count":2, 
    "quorum_type":2
}'
```
**Response:**
```
"Test tokens generated successfully"
```
#### sample with invalid request (invalid input format to number_of_tokens)
```
curl -X POST http://localhost:8080/testrbt/create -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq", "number_of_tokens":1.0}'
```
**Response:**
```
{"error":"Invalid input"}
```

### Curl request to get all FTs' info
```
curl -X GET "http://localhost:8080/get_all_ft?did=<user DID>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/get_all_ft?did=bafybmihtljjkvayu7iwjxzd4sfufywakdd3zymrgcnw7jnc3p6oltjzofe"
```
**Response:**
```
{"ft_info":[{"creator_did":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m","ft_count":2,"ft_name":"test1"}],"message":"Got FT info successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to did)
```
curl -X GET "http://localhost:8080/get_all_ft?did="
```
**Response:**
```
{"error":"Missing required parameters: did"}
```

### Curl request to get FT chain
```
curl -X GET "http://localhost:8080/get_ft_chain?did=<user DID>&tokenID=<FT token ID>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/get_ft_chain?did=bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m&tokenID="
```
**Response:**
```
{"TokenChainData":[{"TCBlockHashKey":"4d2c27b2910d74238511efad8aa554b00e0cb700743ed7e16ccf6dddecb54a1d","TCChildTokensKey":[],"TCGenesisBlockKey":{"GBInfoKey":{"QmX4DscAghtbwavd21qUm197tYSnfpw1ANBtVyhsxXxDjZ":{"GICommitedTokensKey":{},"GIParentIDKey":"QmQfLrqiX1TYKfBAntfqTimBnzmS4grmphMJsBy9KKYrT4","GITokenLevelKey":0,"GITokenNumberKey":1}},"GBTypeKey":""},"TCSignatureKey":{"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m":"3045022100f8e4b21f24bb5b1b400fe4d9b8148a44fd010803c6404ea34335fed1b8fe29e202202e4467a8c22d0a999fa08ccd6f3b8e25f7a32e8b4e0047154ececfd356499e7e"},"TCTokenOwnerKey":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m","TCTokenValueKey":0.1,"TCTransInfoKey":{"TICommentKey":"FT generated at : 2024-12-17 18:38:42.559179681 +0530 IST m=+7928.990494248 for FT Name : test1","TITokensKey":{"QmX4DscAghtbwavd21qUm197tYSnfpw1ANBtVyhsxXxDjZ":{"TTBlockNumberKey":"0","TTPreviousBlockIDKey":"","TTTokenTypeKey":10}}},"TCTransTypeKey":"05"},{"TCBlockHashKey":"35ba03794d5093c59eafb601c7ecf44002ef2d948eb557d7dd08737aa59a05d7","TCChildTokensKey":[],"TCPledgeDetailsKey":{"bafybmiasnd2edbghz4qjhsaghc6g6ghd77slyu7zm75qfyjn6tlgojf6nu":[{"8-1":"QmfDFChvQRst7HGN85Ws4X5CdGEK7NtR2GJmKxXx9jrFYP","8-2":5,"8-3":"0-58ca8c778393777a1e10283724cc69614244b32bc3a293c7316222d73cfe4184"}],"bafybmicgivtxz2hnajemoqq2emw2zzpk6x7ecar3m7gvthhspqakur3lwi":[{"8-1":"QmWfjsr1RXct65dqe5gwz8xtJsUkrX9iwqp96psedMH1cm","8-2":5,"8-3":"0-6becc5961b5e0d03ddf834fabe19370486a1510027f3d457a1a17e7034b27bb2"}],"bafybmig4x5q3ym4z7e53pgdvjfxdqvwsgidfy3yuezdwiqwbbdheqvp6qy":[{"8-1":"QmVG9ViEMw7WgZnsEiUFB1f5VeN66bHbFvfm24LFoz8NZE","8-2":5,"8-3":"0-898fa433bbe6f8054373126ed66a3fdfde160dbe73cdf49c13d4658fc4bd6b5b"}],"bafybmig62a4wy2m6aiab22vsdfgbrkkx2o64yoj3r7blemazuenyhpcgye":[{"8-1":"QmRZUqj54iNSBmk1PspYG46n58CtHASfzp1vfcC2Yt1nei","8-2":5,"8-3":"0-c5ac28d184ac63d658e9556e4d3ecc9a5276d332ad8afecb30618af6624cb36a"}],"bafybmihjk2s5mkiusews26svgoz2xdfabzvh7r44bbz5jv4zkurkhbraay":[{"8-1":"QmTnhE3Ubn1pqZBQynSuJanLdkEsFLYx6V7iFawik3BvNk","8-2":5,"8-3":"0-ff40c79e0460ec65c028b554cc9b961bc9995ec8fa7af3de6246f71bb5a6e601"}]},"TCQuorumSignatureKey":[{"did":"bafybmihjk2s5mkiusews26svgoz2xdfabzvh7r44bbz5jv4zkurkhbraay","hash":"","priv_signature":"3046022100f0d86a587565d9a7215ad9a8ae6b8faf6e765e3c0cd377d59f0847ec44f8b0ae022100c998de4fbbf2947204c83e0595e39ebe7f16f148e14c7b1923fa3125486f76a1","sign_type":"0","signature":""},{"did":"bafybmiasnd2edbghz4qjhsaghc6g6ghd77slyu7zm75qfyjn6tlgojf6nu","hash":"","priv_signature":"3046022100b035ec5e1d0faf8bb005b6d86f982fd4d7753b317f82e50f166c4bdbbb5c31e2022100cdbbfc8a09e65658f765be85ed4019c70aee8ab50371c822077b323b1eefb3d7","sign_type":"0","signature":""},{"did":"bafybmig4x5q3ym4z7e53pgdvjfxdqvwsgidfy3yuezdwiqwbbdheqvp6qy","hash":"","priv_signature":"304502207296ddd62b6a5f718ed4527d827e0d7cd7ea3fb325561696d32851cb10b62a9f022100b6b84f2160a3b27027702cc7c3dff0f25cbd74b0033b296f3c8dace45fcfb742","sign_type":"0","signature":""},{"did":"bafybmicgivtxz2hnajemoqq2emw2zzpk6x7ecar3m7gvthhspqakur3lwi","hash":"","priv_signature":"304502207cf27e366ae6d21404f263bc7bedb028110b0275e16a9fa59a793439fa1b8ec5022100ae60ee4637fa1b2f2b0f05a6d1e00bcd89854248b4e5a97ac1de68c2c8528e73","sign_type":"0","signature":""},{"did":"bafybmig62a4wy2m6aiab22vsdfgbrkkx2o64yoj3r7blemazuenyhpcgye","hash":"","priv_signature":"304402200116878a467fb28c43ce1464afeb6c07fe7aa5a43fe49c3819584544908745db02207399853e65d4aebca9c21f592a950c13f34f5283cb07497b0d300f96dc4012e0","sign_type":"0","signature":""}],"TCSenderSignatureKey":{"InitiatorDID":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m","hash":"2528205ee902d5e537cfb6694ce017931a1cdd6be07e7af2867c803937dc5bb8","nlss_share_signature":"","priv_signature":"304402202fe718ca168deb42817cce1c758625a96e0f81c8a9d38a31ea874696f5a9cfef022003319304e31a81b5bb05f240f552869c48caf457e7be2d82c0306c0f832303c1","sign_type":0},"TCSignatureKey":{"bafybmiasnd2edbghz4qjhsaghc6g6ghd77slyu7zm75qfyjn6tlgojf6nu":"3046022100d3fd3e513e9771f1db516bbd1062fa701532ea2e215f7224995f311ae7707904022100e8d7f6b9860627264d4f2f98e64427fcf1d22034eaa06929535a9ba0d733f85d","bafybmicgivtxz2hnajemoqq2emw2zzpk6x7ecar3m7gvthhspqakur3lwi":"3045022100a73b38829ae5339acb97342e7574088c11acbc4fe0cec7d172dfa9316dbdb13402206f30a77d5e705bb113f1080e43e84789660b45992c4cff238951aed975774f55","bafybmig4x5q3ym4z7e53pgdvjfxdqvwsgidfy3yuezdwiqwbbdheqvp6qy":"3045022100fd624389e98704ff0b7552997d2d119479540551b8921e7b506aa5079ff1632902206fcb1427d068eb8ee8cd592b959bb36ce11cd0b1d531270f8d4910d9ab7f6900","bafybmig62a4wy2m6aiab22vsdfgbrkkx2o64yoj3r7blemazuenyhpcgye":"30450221008e5a0a891f39b097fd20053b47890cddab10b884107ab5233dd671d75b4d9e41022058cd50ac3b8916738198dd292c9779ecdb327bd1c01db1d59089fac8027729ab","bafybmihjk2s5mkiusews26svgoz2xdfabzvh7r44bbz5jv4zkurkhbraay":"3046022100cfa26754467283fabdd41520a59875442e6f71a654121983f6c5ea5c332a6d01022100aa78b089ec7b6d3d5c1a8e03393b0fdf8ebca53148bab1df0435eb6ebc1575c7"},"TCSmartContractKey":"a36131590218a46131086132006133a36131783b62616679626d696873617337657263773275706b7571356d70713278726175777963786b657336707878796a3532696a667837736777737172366d6132783b62616679626d6968746c6a6a6b766179753769776a787a6434736675667977616b6464337a796d7267636e77376a6e633370366f6c746a7a6f66656134a2782e516d57734c6a76424a6d32426f7375374176596a64517167347156464b6a4d6d4a36434c4b78767a454431334243a461310a6132783b62616679626d696873617337657263773275706b7571356d70713278726175777963786b657336707878796a3532696a667837736777737172366d61337842302d646536336464386237626536363434616634373931373061626365353733343539383336666235363164666366323065366130616638326131613738613661316134fb3fb999999999999a782e516d5834447363416768746277617664323171556d3139377459536e66707731414e427456796873785878446a5aa461310a6132783b62616679626d696873617337657263773275706b7571356d70713278726175777963786b657336707878796a3532696a667837736777737172366d61337842302d346432633237623239313064373432333835313165666164386161353534623030653063623730303734336564376531366363663664646465636235346131646134fb3fb999999999999a6134f900006132583fa1783b62616679626d696873617337657263773275706b7571356d70713278726175777963786b657336707878796a3532696a667837736777737172366d60613358cca1783b62616679626d696873617337657263773275706b7571356d70713278726175777963786b657336707878796a3532696a667837736777737172366d788c3330343430323230326665373138636131363864656234323831376363653163373538363235613936653066383163386139643338613331656138373436393666356139636665663032323030333331393330346533316138316235626230356632343066353532383639633438636166343537653762653264383263303330366330663833323330336331","TCTokenOwnerKey":"bafybmihtljjkvayu7iwjxzd4sfufywakdd3zymrgcnw7jnc3p6oltjzofe","TCTransInfoKey":{"TIReceiverDIDKey":"bafybmihtljjkvayu7iwjxzd4sfufywakdd3zymrgcnw7jnc3p6oltjzofe","TISenderDIDKey":"bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m","TITIDKey":"db6d7fb432725708f5d17a1026697965c2354fd91430dd2655e94c3dda424a54","TITokensKey":{"QmWsLjvBJm2Bosu7AvYjdQqg4qVFKjMmJ6CLKxvzED13BC":{"TTBlockNumberKey":"1","TTPreviousBlockIDKey":"0-de63dd8b7be6644af479170abce573459836fb561dfcf20e6a0af82a1a78a6a1","TTTokenTypeKey":10},"QmX4DscAghtbwavd21qUm197tYSnfpw1ANBtVyhsxXxDjZ":{"TTBlockNumberKey":"1","TTPreviousBlockIDKey":"0-4d2c27b2910d74238511efad8aa554b00e0cb700743ed7e16ccf6dddecb54a1d","TTTokenTypeKey":10}}},"TCTransTypeKey":"02"}],"message":"FT tokenchain data fetched successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to tokenID)
```
curl -X GET "http://localhost:8080/get_ft_chain?did=bafybmihsas7ercw2upkuq5mpq2xrauwycxkes6pxxyj52ijfx7sgwsqr6m&tokenID="
```
**Response:**
```
{"error":"Missing required parameters: tokenID"}
```

### Curl request to create NFT
```
curl -X POST "http://localhost:8080/create_nft -d '{"did":"<rubix node DID>", "metadata":<metadata file path>, "artifact":"<artifact file path>"}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/create_nft -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/NFT/test.png"
}'
```
**Response:**
```
"NFT Token generated successfully"
```
#### sample with invalid request (invalid input path to artifact)
```
curl -X POST http://localhost:8080/create_nft -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/test.png"
}'
```
**Response:**
```
{"error":"open /home/maneesha/Rubix-Git/test.png: no such file or directory"}
```

### Curl request to subscribe NFT
```
curl -X POST "http://localhost:8080/subscribe_nft -d '{"did":"<rubix node DID>", "nft":<nft token ID>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/subscribe_nft -d '{
    "did":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq",
    "nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY"
}'
```
**Response:**
```
"NFT subscribed successfully"
```
#### sample with invalid request (invalid input to did)
```
curl -X POST http://localhost:8080/subscribe_nft -d '{
    "did":"",
    "nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY"
}'
```
**Response:**
```
{"error":"User not found"}
```

### Curl request to deploy NFT
```
curl -X POST "http://localhost:8080/deploy_nft -d '{"did":"<rubix node DID>", "nft":"<nft ID>", "quorum_type":<1 or 2>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8080/deploy_nft -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY",
    "quorum_type":2
}'
```
**Response:**
```
"NFT Token generated successfully"
```
#### sample with invalid request (invalid input to quorum_type)
```
curl -X POST http://localhost:8080/deploy_nft -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY",
    "quorum_type":4
}'
```
**Response:**
```
{"error":"test token generation failed, Invalid quorum type"}
```

### Curl request to execute NFT
```
curl -X POST http://localhost:8080/execute_nft -d '{
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
curl -X POST http://localhost:8080/execute_nft -d '{
  "comment": "nft transfer from wallet",
  "nft": "QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY",
  "nft_data": "",
  "nft_value": 10.0,
  "owner": "bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
  "quorum_type": 2,
  "receiver": "bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq"
}'
```
**Response:**
```
"NFT Executed successfully in 2.281952715s"
```
#### sample with invalid request (invalid input )
```
curl -X POST http://localhost:8080/execute_nft -d '{
  "comment": "nft transfer from wallet",
  "nft": "QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY",
  "nft_data": "",
  "nft_value": 5,
  "owner": "bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq",
  "quorum_type": 2,
  "receiver": "bafybmia3zyr73srf5jnm3xuvuetepn5alh53wbtw6ep4pnojey6emtwcmu"
}'
```
**Response:**
```
{"error":"test token generation failed, no records found"}
```

### Curl request to fetch NFT
```
curl -X GET "http://localhost:8080/get_nft?did=<string>&nft=<string>"
```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/get_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&nft=QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY"
```
**Response:**
```
{"message":"NFT fetched successfully","result":null,"status":true}
```
#### sample with invalid request (invalid input path to artifact)
```
curl -X POST http://localhost:8080/create_nft -d '{
    "did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq",
    "metadata":"/home/maneesha/Rubix-Git/NFT/metadata.json",
    "artifact":"/home/maneesha/Rubix-Git/test.png"
}'
```
**Response:**
```
{"error":"open /home/maneesha/Rubix-Git/test.png: no such file or directory"}
```

### Curl request to get NFT chain
```
curl -X GET "http://localhost:8080/get_nft_chain?did=<string>&nft=<string>&latest=<string>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/get_nft_chain?did=bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq&nft=QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY"
```
**Response:**
```
{"NFTDataReply":[{"BlockId":"1-04886a33a4a69f18cd10d6e878edfa6b6dcdc2f354db07e79a64393008707975","BlockNo":1,"NFTData":"","NFTOwner":"bafybmib3tvqlnb25uhpdwv2y4wbhttzmpwdel3nblfou3vu4vzv7b3bybq","NFTValue":10}],"message":"Fetched latest block details of nft","result":null,"status":true}
```
#### sample with invalid request (invalid input to nft)
```
curl -X GET "http://localhost:8080/get_nft_chain?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq&nft=QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfikj"
```
**Response:**
```
{"NFTDataReply":null,"message":"Failed to get nft data, token does not exist","result":null,"status":false}
```

### Curl request to get all NFTs
```
curl -X GET "http://localhost:8080/get_all_nft?did=<string>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8080/get_all_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq"
```
**Response:**
```
{"message":"Got All NFTs","nfts":[{"nft":"QmSYAeRRoxurxEpraDGu4B9fUn38VP7vXBoxzZqQnmfijY","nft_value":0,"owner_did":"bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamnq"}],"result":null,"status":true}
```
#### sample with invalid request (invalid input to did)
```
curl -X GET "http://localhost:8080/get_all_nft?did=bafybmifebqlvq2uetxo3mgrwugf3k4rdjupo6h6fkn7mzrb5ekhxttamjh"
```
**Response:**
```
{"error":"User not found"}
```
