import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('application-key-management')

def save_keys(application_id, public_key, private_key): 

    table.put_item(
        Item={
            'applicationId': application_id,
            'name': application_id,
            'privateKey': private_key,
            'pubKey': public_key
            }
    )

def get_public_key(application_id):
    
    key = get_key_management(application_id)
    public_key = key['pubKey']

    return public_key

def get_private_key(application_id):

    key = get_key_management(application_id)
    private_key = key['privateKey']

    return private_key

def get_key_management(application_id):

    response = table.get_item(
        Key={
            'applicationId': application_id,
        }
    )

    item = response['Item']

    return item
