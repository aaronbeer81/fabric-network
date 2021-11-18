#!/bin/bash

FABRIC_SERVER_HOME=/etc/hyperledger/fabric-ca-server
LOCAL_CRYPTO_HOME=./artifacts/crypto-config
ORDERER_SUBDIRECTORY=/ca-orderer/ordererOrganizations/orderer
PEER_SUBDIRECTORY=/ca-peer/peerOrganizations/peer
TIMEOUT_TIME=180s

kubectl apply -f k8s/bootstrap
kubectl wait --timeout=180s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=fabric-inspector -o jsonpath="{.items[0].metadata.name}")
kubectl cp ./artifacts/fabric-config $(kubectl get pod -l app.kubernetes.io/name=fabric-inspector -o jsonpath="{.items[0].metadata.name}"):/

sleep 10

echo "---- START CLI CONTAINER ----"
kubectl apply -f k8s/deployment/cli
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}")

echo "---- START ROOT-CA ----"
kubectl apply -f k8s/deployment/ca-root
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-root -o jsonpath="{.items[0].metadata.name}")

sleep 10

echo "---- COPY ROOT-CA CERT ----"
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=ca-root -o jsonpath="{.items[0].metadata.name}"):$FABRIC_SERVER_HOME/tls-cert.pem $LOCAL_CRYPTO_HOME/ca-root/tls-cert.pem
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'mkdir /etc/hyperledger/fabric/ca-root'
kubectl cp $LOCAL_CRYPTO_HOME/ca-root/tls-cert.pem $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-root/tls-cert.pem

echo "---- ENROLL ROOT-CA REGISTRAR----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-root:password@ca-root:7131 --tls.certfiles /etc/hyperledger/fabric/ca-root/tls-cert.pem -M /etc/hyperledger/fabric/ca-root/registrar-ca-root/msp'

echo "---- REGISTER INTERMEDIATE-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name caintermediateadmin-ca-root --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-root:password@ca-root:7131 --tls.certfiles /etc/hyperledger/fabric/ca-root/tls-cert.pem -M /etc/hyperledger/fabric/ca-root/registrar-ca-root/msp'

echo "---- ENROLL INTERMEDIATE-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://caintermediateadmin-ca-root:password@ca-root:7131 --tls.certfiles /etc/hyperledger/fabric/ca-root/tls-cert.pem -M /etc/hyperledger/fabric/ca-root/caintermediateadmin-ca-root/msp'

echo "---- START INTERMEDIATE-CA ----"
kubectl apply -f k8s/deployment/ca-intermediate
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-intermediate -o jsonpath="{.items[0].metadata.name}")

sleep 10

echo "---- COPY INTERMEDIATE-CA CERTS ----"
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=ca-intermediate -o jsonpath="{.items[0].metadata.name}"):$FABRIC_SERVER_HOME/tls-cert.pem $LOCAL_CRYPTO_HOME/ca-intermediate/tls-cert.pem
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'mkdir /etc/hyperledger/fabric/ca-intermediate'
kubectl cp $LOCAL_CRYPTO_HOME/ca-intermediate/tls-cert.pem $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-intermediate/tls-cert.pem

echo "---- ENROLL INTERMEDIATE-CA REGISTRAR----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/registrar-ca-intermediate/msp'

echo "---- REGISTER TLSPEER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name tlscapeeradmin-ca-intermediate --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/registrar-ca-intermediate/msp'

echo "---- ENROLL TLSPEER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://tlscapeeradmin-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/tlscapeeradmin-ca-intermediate/msp'

echo "---- REGISTER TLSORDERER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name tlscaordereradmin-ca-intermediate --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/registrar-ca-intermediate/msp'

echo "---- ENROLL TLSORDERER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://tlscaordereradmin-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/tlscaordereradmin-ca-intermediate/msp'

echo "---- REGISTER PEER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name capeeradmin-ca-intermediate --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/registrar-ca-intermediate/msp'

echo "---- ENROLL PEER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://capeeradmin-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/capeeradmin-ca-intermediate/msp'

echo "---- REGISTER ORDERER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name caordereradmin-ca-intermediate --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/registrar-ca-intermediate/msp'

echo "---- ENROLL ORDERER-CA ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://caordereradmin-ca-intermediate:password@ca-intermediate:7131 --tls.certfiles /etc/hyperledger/fabric/ca-intermediate/tls-cert.pem -M /etc/hyperledger/fabric/ca-intermediate/caordereradmin-ca-intermediate/msp'

echo "---- START TLS-CAs ----"
kubectl apply -f k8s/deployment/ca-tlspeer -f k8s/deployment/ca-tlsorderer
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-tlspeer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-tlsorderer -o jsonpath="{.items[0].metadata.name}")

sleep 10

echo "---- COPY TLS-CA CERTS ----"
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=ca-tlspeer -o jsonpath="{.items[0].metadata.name}"):$FABRIC_SERVER_HOME/ca-cert.pem $LOCAL_CRYPTO_HOME/ca-tlspeer/tls-ca-cert.pem
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=ca-tlsorderer -o jsonpath="{.items[0].metadata.name}"):$FABRIC_SERVER_HOME/ca-cert.pem $LOCAL_CRYPTO_HOME/ca-tlsorderer/tls-ca-cert.pem
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'mkdir /etc/hyperledger/fabric/ca-tlsorderer; mkdir /etc/hyperledger/fabric/ca-tlspeer;'
kubectl cp $LOCAL_CRYPTO_HOME/ca-tlsorderer/tls-ca-cert.pem $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem
kubectl cp $LOCAL_CRYPTO_HOME/ca-tlspeer/tls-ca-cert.pem $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem

echo "---- ENROLL TLSPEER-CA REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/ca-tlspeer-registrar/msp'

echo "---- REGISTER PEER-CA TLS-ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name capeeradmin-ca-tlspeer --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/ca-tlspeer-registrar/msp'

echo "---- ENROLL PEER-CA TLS-ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts ca-peer -u https://capeeradmin-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/capeeradmin-ca-tlspeer/msp'

echo "---- ENROLL TLSORDERER-CA TLS-REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'

echo "---- REGISTER ORDERER-CA TLS-ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name caordereradmin-ca-tlsorderer --id.secret password --id.type admin --id.attrs hf.IntermediateCA=true -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'

echo "---- ENROLL ORDERER-CA TLS-ADMIN ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts ca-orderer -u https://caordereradmin-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/caordereradmin-ca-tlsorderer/msp'

echo "---- COPY TLS-CRYPTO MATERIAL TO LOCAL DIRECTORIES ----"
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-tlspeer $LOCAL_CRYPTO_HOME/ca-tlspeer
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-tlsorderer $LOCAL_CRYPTO_HOME/ca-tlsorderer

echo "---- COPY TLS-CRYPTO MATERIAL TO ORG-CAs ----"
mkdir -p $LOCAL_CRYPTO_HOME/ca-peer/tls
mv $LOCAL_CRYPTO_HOME/ca-tlspeer/capeeradmin-ca-tlspeer/msp/keystore/*_sk $LOCAL_CRYPTO_HOME/ca-tlspeer/capeeradmin-ca-tlspeer/msp/keystore/priv_sk
cp $LOCAL_CRYPTO_HOME/ca-tlspeer/capeeradmin-ca-tlspeer/msp/signcerts/cert.pem $LOCAL_CRYPTO_HOME/ca-peer/tls/cert.pem
cp $LOCAL_CRYPTO_HOME/ca-tlspeer/capeeradmin-ca-tlspeer/msp/keystore/priv_sk $LOCAL_CRYPTO_HOME/ca-peer/tls/priv_sk
cp $LOCAL_CRYPTO_HOME/ca-tlspeer/tls-ca-cert.pem $LOCAL_CRYPTO_HOME/ca-peer/tls-ca-cert.pem
mkdir -p $LOCAL_CRYPTO_HOME/ca-orderer/tls
mv $LOCAL_CRYPTO_HOME/ca-tlsorderer/caordereradmin-ca-tlsorderer/msp/keystore/*_sk $LOCAL_CRYPTO_HOME/ca-tlsorderer/caordereradmin-ca-tlsorderer/msp/keystore/priv_sk
cp $LOCAL_CRYPTO_HOME/ca-tlsorderer/caordereradmin-ca-tlsorderer/msp/signcerts/cert.pem $LOCAL_CRYPTO_HOME/ca-orderer/tls/cert.pem
cp $LOCAL_CRYPTO_HOME/ca-tlsorderer/caordereradmin-ca-tlsorderer/msp/keystore/priv_sk $LOCAL_CRYPTO_HOME/ca-orderer/tls/priv_sk
cp $LOCAL_CRYPTO_HOME/ca-tlsorderer/tls-ca-cert.pem $LOCAL_CRYPTO_HOME/ca-orderer/tls-ca-cert.pem
kubectl cp $LOCAL_CRYPTO_HOME $(kubectl get pod -l app.kubernetes.io/name=fabric-inspector -o jsonpath="{.items[0].metadata.name}"):/

echo "---- START ORG-CAs ----"
kubectl apply -f k8s/deployment/ca-peer -f k8s/deployment/ca-orderer
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-peer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=$TIMEOUT_TIME --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=ca-orderer -o jsonpath="{.items[0].metadata.name}")

sleep 10

echo "---- GENERATE CRYPTO MATERIAL FROM CLI CONTAINER ----"
echo "---- ENROLLING PEER REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-peer:password@ca-peer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-peer/tls/cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/registrar-ca-peer/msp'
echo "---- REGISTERING PEERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name peer1-peer --id.secret password --id.type peer -u https://registrar-ca-peer:password@ca-peer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-peer/tls/cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/registrar-ca-peer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name peer2-peer --id.secret password --id.type peer -u https://registrar-ca-peer:password@ca-peer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-peer/tls/cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/registrar-ca-peer/msp'
echo "---- ENROLLING PEERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://peer1-peer:password@ca-peer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-peer/tls/cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/peers/peer1-peer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://peer2-peer:password@ca-peer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-peer/tls/cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/peers/peer2-peer/msp'

echo "---- ENROLLING ORDERER REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://registrar-ca-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/registrar-ca-orderer/msp'
echo "---- REGISTERING ORDERERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer1-orderer --id.secret password --id.type orderer -u https://registrar-ca-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/registrar-ca-orderer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer2-orderer --id.secret password --id.type orderer -u https://registrar-ca-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/registrar-ca-orderer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer3-orderer --id.secret password --id.type orderer -u https://registrar-ca-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/registrar-ca-orderer/msp'
echo "---- ENROLLING ORDERERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://orderer1-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer1-orderer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://orderer2-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer2-orderer/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile ca -u https://orderer3-orderer:password@ca-orderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-orderer/tls/cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer3-orderer/msp'

echo "---- ENROLLING TLS PEER REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls -u https://registrar-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/ca-tlspeer-registrar/msp'
echo "---- REGISTER TLS PEERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name peer1-peer --id.secret password --id.type peer -u https://registrar-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/ca-tlspeer-registrar/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name peer2-peer --id.secret password --id.type peer -u https://registrar-ca-tlspeer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlspeer/ca-tlspeer-registrar/msp'
echo "---- ENROLL TLS PEERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts peer1-peer,peer1 -u https://peer1-peer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/peers/peer1-peer/tls'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts peer2-peer,peer2 -u https://peer2-peer:password@ca-tlspeer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlspeer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-peer/peerOrganizations/peer/peers/peer2-peer/tls'

echo "---- ENROLLING TLS ORDERER REGISTRAR ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'
echo "---- REGISTER TLS ORDERERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer1-orderer --id.secret password --id.type orderer -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer2-orderer --id.secret password --id.type orderer -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client register --id.name orderer3-orderer --id.secret password --id.type orderer -u https://registrar-ca-tlsorderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-tlsorderer/ca-tlsorderer-registrar/msp'
echo "---- ENROLL TLS ORDERERS ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts orderer1-orderer,orderer1 -u https://orderer1-orderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer1-orderer/tls'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts orderer2-orderer,orderer2 -u https://orderer2-orderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer2-orderer/tls'
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c 'fabric-ca-client enroll --enrollment.profile tls --csr.hosts orderer3-orderer,orderer3 -u https://orderer3-orderer:password@ca-tlsorderer:7131 --tls.certfiles /etc/hyperledger/fabric/ca-tlsorderer/tls-ca-cert.pem -M /etc/hyperledger/fabric/ca-orderer/ordererOrganizations/orderer/orderers/orderer3-orderer/tls'

echo "---- RESTRUCTURE CRYPTO-MATERIAL ON CLI ----"
kubectl exec -it $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}") -- /bin/bash -c '
  CRYPTO_CONFIG=/etc/hyperledger/fabric;
  ORDERER_ORG=/ca-orderer/ordererOrganizations/orderer;
  PEER_ORG=/ca-peer/peerOrganizations/peer;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/msp/cacerts/ca-orderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/msp/cacerts/ca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/msp/cacerts/ca-orderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/msp/cacerts/ca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/msp/cacerts/ca-orderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/msp/cacerts/ca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/msp/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/msp/keystore/priv_sk;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/msp/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/msp/keystore/priv_sk;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/msp/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/msp/keystore/priv_sk;
  mkdir -p $CRYPTO_CONFIG$ORDERER_ORG/msp/cacerts;
  cp $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/msp/cacerts/ca-orderer.pem $CRYPTO_CONFIG$ORDERER_ORG/msp/cacerts/ca-orderer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/msp/cacerts/ca-peer-7131.pem $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/msp/cacerts/ca-peer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/msp/cacerts/ca-peer-7131.pem $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/msp/cacerts/ca-peer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/msp/keystore/*_sk $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/msp/keystore/priv_sk;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/msp/keystore/*_sk $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/msp/keystore/priv_sk;
  mkdir -p $CRYPTO_CONFIG$PEER_ORG/msp/cacerts;
  cp $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/msp/cacerts/ca-peer.pem $CRYPTO_CONFIG$PEER_ORG/msp/cacerts/ca-peer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/tls/tlscacerts/tls-ca-tlsorderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/tls/tlscacerts/tlsca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/tls/tlscacerts/tls-ca-tlsorderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/tls/tlscacerts/tlsca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/tls/tlscacerts/tls-ca-tlsorderer-7131.pem $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/tls/tlscacerts/tlsca-orderer.pem;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/tls/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/tls/keystore/priv_sk;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/tls/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer2-orderer/tls/keystore/priv_sk;
  mv $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/tls/keystore/*_sk $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer3-orderer/tls/keystore/priv_sk;
  mkdir -p $CRYPTO_CONFIG$ORDERER_ORG/msp/tlscacerts;
  cp $CRYPTO_CONFIG$ORDERER_ORG/orderers/orderer1-orderer/tls/tlscacerts/tlsca-orderer.pem $CRYPTO_CONFIG$ORDERER_ORG/msp/tlscacerts/tlsca-orderer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/tls/tlscacerts/tls-ca-tlspeer-7131.pem $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/tls/tlscacerts/tlsca-peer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/tls/tlscacerts/tls-ca-tlspeer-7131.pem $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/tls/tlscacerts/tlsca-peer.pem;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/tls/keystore/*_sk $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/tls/keystore/priv_sk;
  mv $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/tls/keystore/*_sk $CRYPTO_CONFIG$PEER_ORG/peers/peer2-peer/tls/keystore/priv_sk;
  mkdir -p $CRYPTO_CONFIG$PEER_ORG/msp/tlscacerts;
  cp $CRYPTO_CONFIG$PEER_ORG/peers/peer1-peer/tls/tlscacerts/tlsca-peer.pem $CRYPTO_CONFIG$PEER_ORG/msp/tlscacerts/tlsca-peer.pem;'

echo "---- COPY CRYPTO MATERIAL TO LOCAL DIRECTORIES ----"
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-peer $LOCAL_CRYPTO_HOME/ca-peer
kubectl cp $(kubectl get pod -l app.kubernetes.io/name=cli-peer -o jsonpath="{.items[0].metadata.name}"):/etc/hyperledger/fabric/ca-orderer $LOCAL_CRYPTO_HOME/ca-orderer

echo "---- PREPARE & GENERATE GENESIS BLOCK ----"
cp ./artifacts/static-block/ca-orderer/config.yaml $LOCAL_CRYPTO_HOME$ORDERER_SUBDIRECTORY/msp/config.yaml
cp ./artifacts/static-block/ca-orderer/config.yaml $LOCAL_CRYPTO_HOME$ORDERER_SUBDIRECTORY/orderers/orderer1-orderer/msp/config.yaml
cp ./artifacts/static-block/ca-orderer/config.yaml $LOCAL_CRYPTO_HOME$ORDERER_SUBDIRECTORY/orderers/orderer2-orderer/msp/config.yaml
cp ./artifacts/static-block/ca-orderer/config.yaml $LOCAL_CRYPTO_HOME$ORDERER_SUBDIRECTORY/orderers/orderer3-orderer/msp/config.yaml
cp ./artifacts/static-block/ca-orderer/config.yaml $LOCAL_CRYPTO_HOME$ORDERER_SUBDIRECTORY/ca-orderer-admin/msp/config.yaml

cp ./artifacts/static-block/ca-peer/config.yaml $LOCAL_CRYPTO_HOME$PEER_SUBDIRECTORY/msp/config.yaml
cp ./artifacts/static-block/ca-peer/config.yaml $LOCAL_CRYPTO_HOME$PEER_SUBDIRECTORY/peers/peer1-peer/msp/config.yaml
cp ./artifacts/static-block/ca-peer/config.yaml $LOCAL_CRYPTO_HOME$PEER_SUBDIRECTORY/peers/peer2-peer/msp/config.yaml
cp ./artifacts/static-block/ca-peer/config.yaml $LOCAL_CRYPTO_HOME$PEER_SUBDIRECTORY/ca-peer-admin/msp/config.yaml

configtxgen -outputBlock ./artifacts/fabric-config/orderers/genesis/genesis.block -profile Genesis -channelID system-channel -configPath ./artifacts/fabric-config

echo "---- PUT CRYPTO MATERIAL BACK ON CRYPTO-CONFIG PVC ----"
kubectl cp $LOCAL_CRYPTO_HOME $(kubectl get pod -l app.kubernetes.io/name=fabric-inspector -o jsonpath="{.items[0].metadata.name}"):/

echo "---- START PEERS AND ORDERERS ----"
kubectl apply -f k8s/deployment/peer1 -f k8s/deployment/peer2 -f k8s/deployment/orderer1 -f k8s/deployment/orderer2 -f k8s/deployment/orderer3
kubectl wait --timeout=30s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=peer1-peer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=30s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=peer2-peer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=30s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=orderer1-orderer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=30s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=orderer2-orderer -o jsonpath="{.items[0].metadata.name}")
kubectl wait --timeout=30s --for=condition=Ready pod/$(kubectl get pod -l app.kubernetes.io/name=orderer3-orderer -o jsonpath="{.items[0].metadata.name}")