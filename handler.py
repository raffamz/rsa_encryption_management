import json

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

from Crypto.PublicKey import RSA
import base64

import db

def key_generation_handler(event, context):

    try:
        headers = event['headers']
        application_id = headers['applicationId']

        logger.info('Gerando chave para o application_id {}'.format(application_id))

        new_key = RSA.generate(2048, e=65537)
        public_key = new_key.publickey().exportKey("PEM").decode("utf-8")
        private_key = new_key.exportKey("PEM").decode("utf-8")

        print(public_key)
        print(private_key)
        #db.save_keys(application_id, public_key, private_key)

        body = {
            'publicKey': public_key
        }

        response = {
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True
            },
            'statusCode': 200,
            'body': json.dumps(body)
        }

        logger.info('Chave gerada para o application_id {}'.format(application_id))

        return response

    except KeyError as ex:

        logger.error('O atributo {} esta faltando'.format(ex))

        body = {
            'message': 'Attribute {} is missing'.format(ex)
        }

        response = {
            'statusCode': 500,
            'body': json.dumps(body)
        }

        return response

    except Exception as ex:

        logger.error('Houve um erro nao tratado: {}'.format(ex))

        body = {
            'message': 'An error occured.',
        }

        response = {
            'statusCode': 500,
            'body': json.dumps(body)
        }

        return response

def encrypt_handler(event, context):

    try:

        headers = event['headers']
        application_id = headers['applicationId']
        payload = event['body']

        logger.info('Criptografando payload para o application_id {}'.format(application_id))

        public_key = db.get_public_key(application_id)
        public_key = RSA.importKey(public_key)

        payload_encrypted = public_key.encrypt(json.dumps(payload).encode('utf-8'), 32)

        response = {
            'statusCode': 200,
            'body': json.dumps({"payload_encrypted": base64.b64encode(payload_encrypted[0]).decode()})
        }

        logger.info('Payload criptografado para o application_id {}'.format(application_id))

        return response

    except KeyError as ex:

        logger.error('O atributo {} esta faltando'.format(ex))

        body = {
            'message': 'Attribute {} is missing'.format(ex)
        }

        response = {
            'statusCode': 403,
            'body': json.dumps(body)
        }

        return response

    except Exception as ex:

        logger.error('Houve um erro nao tratado: {}'.format(ex))

        body = {
            'message': 'An error occured.',
        }

        response = {
            'statusCode': 500,
            'body': json.dumps(body)
        }

        return response

def decrypt_handler(event, context):
    try:
        headers = event['headers']
        application_id = headers['applicationId']

        payload = event['body']['payload_encrypted']
        payload = base64.b64decode(payload)

        logger.info('Descriptografando payload para o application_id {}'.format(application_id))

        private_key = db.get_private_key(application_id)
        private_key = RSA.importKey(private_key)

        payload_decrypted = private_key.decrypt(payload)

        response = {
            'statusCode': 200,
            'body': json.dumps({"payload_decrypted": json.loads(payload_decrypted.decode())})
        }

        logger.info('Payload descriptografado para o application_id {}'.format(application_id))

        return response

    except KeyError as ex:

        logger.error('O atributo {} esta faltando'.format(ex))

        body = {
            'message': 'Attribute {} is missing'.format(ex)
        }

        response = {
            'statusCode': 403,
            'body': json.dumps(body)
        }

        return response

    except Exception as ex:

        logger.error('Houve um erro nao tratado: {}'.format(ex))

        body = {
            'message': 'An error occured.',
        }

        response = {
            'statusCode': 500,
            'body': json.dumps(body)
        }

        return response
