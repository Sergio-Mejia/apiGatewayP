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

def executeRequests():
    """Ejecuta el request"""

    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-pulpas"] + request.path
    try:
        data = request.json
    except:
        data = None
    if request.method == "GET":
        response = requests.get(url, headers=headers, json=data)
    elif request.method == "POST":
        response = requests.post(url, headers=headers, json=data)
    elif request.method == 'PUT':
        response = requests.put(url, headers=headers, json=data)
    elif request.method == "PATCH":
        response = requests.patch(url, headers=headers, json=data)
    elif request.method == "DELETE":
        response = requests.delete(url, headers=headers, json=data)
    else:
        abort(make_response("Metodo NO disponible", 405))

    return response.json()


@app.route("/consulta/get_pedido_fruta", methods=["GET"])  # noqa: 501
def getResultados():
    """Obtener Resultados"""
    return jsonify(executeRequests())

@app.route("/fruta/create", methods=["POST"])
def frutaCreate():
    """Crear Fruta"""
    return jsonify(executeRequests())

@app.route("/fruta/update", methods=["PATCH"])
def updateFruta():
    return jsonify(executeRequests())

@app.route("/fruta/get", methods=["GET"])
def getFruta():
    return jsonify(executeRequests())

@app.route("/fruta/delete", methods=["DELETE"])
def deleteFruta():
    return jsonify(executeRequests())

@app.route("/precio/create", methods=["POST"])
def precioCreate():
    """Crear Fruta"""
    return jsonify(executeRequests())

@app.route("/precio/update", methods=["PATCH"])
def updatePrecio():
    return jsonify(executeRequests())

@app.route("/precio/get", methods=["GET"])
def getPrecio():
    return jsonify(executeRequests())

@app.route("/precio/delete", methods=["DELETE"])
def deletePrecio():
    return jsonify(executeRequests())

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
