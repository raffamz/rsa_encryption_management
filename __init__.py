import handler



handler.key_generation_handler({"headers":{"applicationId":5}},"")

payload={"username":"0992995574757","password":"Qwert123$%"}
payload_encrypted=handler.encrypt_handler({"headers":{"applicationId":5},"body":payload},"")

payload=handler.encrypt_handler({"headers":{"applicationId":5},"body":{"payload_encrypted":payload_encrypted}},"")
