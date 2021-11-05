from jaeger_client import Config

config = Config(
    config={
        "sampler": {
            "type": "const",
            "param": 1,
        },
        "logging": True,
    },
    service_name="auth-api",
    validate=True,
)


jaeger_tracer = config.initialize_tracer()
