from flask import Flask
from flask import jsonify
from flask import request
from flask import abort, make_response
from flask_cors import CORS
import json
from waitress import serve
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import JWTManager
import datetime
import re

import requests

app=Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"]="super-secret"
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-security"]+'/usuarios/validate'
    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["cedula"]})
    else:
        return jsonify({"Message": "Bad username or password"}), 401



@app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login"]
    if excludedRoutes.__contains__(request.path):
        print("ruta excluida ", request.path)
        pass
    elif request.path == "/usuarios" and request.method in ['POST']:
        print("ruta excluida signup", request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["idRol"]is not None:
            tienePersmiso=validarPermiso(endPoint,request.method,usuario["idRol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url: str) -> str:
    """Elimina el valor Restante de la URL"""
    url_search = re.search('(\/.*\/)', url)  # noqa: 605
    if url_search:
        return url_search.group(1) + "?"
    else:
        return url + "/?"

def validarPermiso(endPoint: str, metodo: str, idRol: str) -> bool:
    """Valida si el token tiene acceso al endpoint especifico"""
    url = dataConfig["url-backend-security"] + "/rolpermiso/validar-permiso/rol/" + str(idRol)  # noqa: 501
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {"url": endPoint, "metodo": metodo}
    response = requests.get(url, json=body, headers=headers)
    try:
        if response.status_code == 200:
            tienePermiso = True
    except:
        pass
    return tienePermiso

def executeRequests(origen: str) -> dict:
    if origen == "pulpas":
        url = dataConfig["url-backend-pulpas"] + request.path
    else:
        url = dataConfig["url-backend-security"] + request.path

    data = None
    try:
        data = request.json
    except:
        pass
    if len(request.args) >= 1:
        url = url + '?'
        k = 0
        for key in request.args.keys():
            if k > 0:
                url = url + "&"
            url = url + key + "=" + request.args[key]
            k = k + 1

    if request.method == "GET":
        response = requests.get(url, json=data)
    elif request.method == "POST":
        response = requests.post(url, json=data)
    elif request.method == "PUT":
        response = requests.put(url, json=data)
    elif request.method == "PATCH":
        response = requests.patch(url, json=data)
    elif request.method == "DELETE":
        response = requests.delete(url, json=data)
    else:
        abort(make_response("Metodo NO disponible", 405))

    if response.status_code == 204:
        return abort(make_response("Borrado", 204))
    else:
        response_msg = response.json()
        try:
            if response_msg.get("code"):
                response_code = response_msg.get("code")
            else:
                response_code = response.status_code
        except:
            response_code = response.status_code
        response = make_response(response_msg, response_code)
        return response


@app.route("/consulta/<any('get_pedido_fruta', 'suma_total'):segment>", methods=["GET"])  # noqa: 501
def getResultados(segment):
    """Obtener Resultados"""
    return executeRequests("pulpas")

@app.route("/fruta/create", methods=["POST"])
def frutaCreate():
    """Crear Fruta"""
    return executeRequests("pulpas")

@app.route("/fruta/update", methods=["PATCH"])
def updateFruta():
    return executeRequests("pulpas")

@app.route("/fruta/get", methods=["GET"])
def getFruta():
    return executeRequests("pulpas")

@app.route("/fruta/delete", methods=["DELETE"])
def deleteFruta():
    return executeRequests("pulpas")

@app.route("/precio/create", methods=["POST"])
def precioCreate():
    """Crear Fruta"""
    return executeRequests("pulpas")

@app.route("/precio/update", methods=["PATCH"])
def updatePrecio():
    return executeRequests("pulpas")

@app.route("/precio/get", methods=["GET"])
def getPrecio():
    return executeRequests("pulpas")

@app.route("/precio/delete", methods=["DELETE"])
def deletePrecio():
    return executeRequests("pulpas")


@app.route("/peso/create", methods=["POST"])
def pesoCreate():
    """Crear Fruta"""
    return executeRequests("pulpas")

@app.route("/peso/update", methods=["PATCH"])
def updatePeso():
    return executeRequests("pulpas")

@app.route("/peso/get", methods=["GET"])
def getPeso():
    return executeRequests("pulpas")

@app.route("/peso/delete", methods=["DELETE"])
def deletePeso():
    return executeRequests("pulpas")



@app.route("/pedido/create", methods=["POST"])
def pedidoCreate():
    """Crear Fruta"""
    return executeRequests("pulpas")

@app.route("/pedido/update", methods=["PATCH"])
def updatePedido():
    return executeRequests("pulpas")

@app.route("/pedido/get", methods=["GET"])
def getPedido():
    return executeRequests("pulpas")

@app.route("/pedido/delete", methods=["DELETE"])
def deletePedido():
    return executeRequests("pulpas")

@app.route("/usuarios", methods=['POST', 'PATCH', 'GET', 'DELETE'])
def usuario():
    if request.method == 'PATCH' and request.json.get("password") == "":
        abort(make_response("Se debe Incluir Contraseña", 422))
    return executeRequests("security")

@app.route("/",methods=['GET'])
def test():
    json = {}
    json["message"]="Server running ..."
    return jsonify(json)



def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data


if __name__=='__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"+dataConfig["url-backend"]+":" + str(dataConfig["port"]))
    serve(app,host=dataConfig["url-backend"],port=dataConfig["port"])
