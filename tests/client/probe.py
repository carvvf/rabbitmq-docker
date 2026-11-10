"""Exercise the broker using the maintained Pika AMQP client and standard HTTP/TLS."""

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request

import pika

mode = sys.argv[1]
context = ssl.create_default_context(cafile="/tls/ca.crt")
credentials = pika.PlainCredentials("image-test", "image-test-password")

if mode == "publish":
    request = urllib.request.Request("https://broker:15671/api/overview")
    authorization = base64.b64encode(b"image-test:image-test-password").decode()
    request.add_header("Authorization", "Basic " + authorization)
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        if not json.load(response).get("rabbitmq_version", "").startswith("4.4."):
            raise RuntimeError("Unexpected management API version")
    try:
        urllib.request.urlopen("https://broker:15671/api/overview", context=context, timeout=15)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
    else:
        raise RuntimeError("Unauthenticated management access was accepted")

parameters = pika.ConnectionParameters(
    host="broker", port=5671, credentials=credentials,
    ssl_options=pika.SSLOptions(context, "broker"), socket_timeout=15,
    blocked_connection_timeout=15,
)
with pika.BlockingConnection(parameters) as connection:
    channel = connection.channel()
    channel.queue_declare(queue="image-persistence", durable=True, arguments={"x-queue-type": "quorum"})
    if mode == "publish":
        channel.confirm_delivery()
        channel.basic_publish("", "image-persistence", b"persistent-image-test", mandatory=True,
                              properties=pika.BasicProperties(delivery_mode=2))
    elif mode == "consume":
        method, properties, body = channel.basic_get("image-persistence", auto_ack=False)
        if method is None or body != b"persistent-image-test" or properties.delivery_mode != 2:
            raise RuntimeError("Confirmed persistent message did not survive restart")
        channel.basic_ack(method.delivery_tag)
        channel.queue_delete("image-persistence")
    else:
        raise RuntimeError("Unknown probe mode")
print(f"AMQP TLS {mode} passed")
