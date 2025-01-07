def on_msg(r):
    msg = r.msg
    # print("id", r.client_id)
    #r.log("{}".format(msg)) 
    r.send("py test ok")
    r.send("py test send {}".format(msg))
    #r.send_others("others send {}".format(msg))
    r.broadcast("broadcast")
    r.log("=======TEST==========================")
    r.send("test .log ok")
