import os

Import("env")
config = env.GetProjectConfig()
config.set("env:" + env["PIOENV"], "custom_nanopb_protos", "+<" + os.getcwd() + "/proto/HomeKeyData.proto>")