import handler
import json

defult_event = {
    'headers': {
        'applicationId': 'tddAplication'
    }
}

def test_generate_key():

    response = handler.key_generation_handler(defult_event, None)

    assert response['statusCode'] == 200

def test_encrypt_and_decrypt_handler():

    event = defult_event
    payload_decrypted = { 'teste': 'teste' }
    event['body'] =  payload_decrypted

    response = handler.encrypt_handler(event, None)

    assert response['statusCode'] == 200

    encrypt_body = json.loads(response['body'])
    event['body'] = encrypt_body
    response = handler.decrypt_handler(event, None)

    assert response['statusCode'] == 200
    assert  json.loads(response['body'])['payload_decrypted'] == payload_decrypted
