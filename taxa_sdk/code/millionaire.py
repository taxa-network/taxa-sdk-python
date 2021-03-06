import json
import binascii

@taxa.route("/submit")
def submit():
    rawData = json.loads(request.data)
    my_id = binascii.b2a_base64(taxa.globals.getUserCert())[:8]
    my_value = rawData["value"]
    session[my_id] = my_value
    response.add("TAXA:%s" % taxa.globals.getUserCert())

@taxa.route("/reveal")
def reveal():
    rawData = json.loads(request.data)
    my_id = binascii.b2a_base64(taxa.globals.getUserCert())[:8]
    my_opponent = rawData["opponent"][:8]

    if my_opponent not in session:
        response.add("Opponent doesn't exist")
        return

    if session[my_id] >= session[my_opponent]:
        response.add("Your value is no less than your opponent")
    else:
        response.add("Your value is less than your opponent")

@taxa.route("/broke")
def broke():
    """
    For testing the errror handling functionality. Should invoke a NameError.
    """
    aa
