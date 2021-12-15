from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import socket
import threading


class Sockets():
    def __init__(self, nombre):
        # Atributos del objeto
        self.nombre = nombre
        self.ip = '127.0.0.10'

        self.node_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket servidor 
        self.node_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket cliente 
        
        self.puerto_origen = int(input("Escribe el puerto origen: ")) # Puerto que se asigna al servidor
        self.puerto_destino = int(input("Escribe el puerto destino: ")) # Puerto al cual se conectará el cliente

        self.llave_pub, self.llave_priv = self.generar_llaves()

    # ---------> Métodos para cifrar <-----------
    def generar_llaves(self):
        llaves = RSA.generate(1024)
        priv = llaves.exportKey()
        pub = llaves.publickey().exportKey()
        return pub, priv
    
    def codificar64(self, msj: str):
        # Convertir la cadena en bytes
        mensaje_bytes = msj.encode('utf-8')
        # Codificar base64
        mensaje_base64 = base64.b64encode(mensaje_bytes)
        return mensaje_base64

    def cifrar_msj(self, pub_key: str, msj: str):
        llave_publica = RSA.importKey(pub_key)
        cifrador_rsa = PKCS1_OAEP.new(llave_publica)
        msm_cifrado = cifrador_rsa.encrypt(self.codificar64(msj))
        return msm_cifrado

    def decodificar64(self, msj: bytes):
        # Decodificar base64
        mensaje_base_64 = base64.b64decode(msj)
        # Convertir los bytes en cadena
        mensaje_claro = mensaje_base_64.decode('utf-8')
        return mensaje_claro

    def descifrar_msj(self, priv_key:str, msj: bytes):
        llave_privada = RSA.importKey(priv_key)
        cifrador_rsa = PKCS1_OAEP.new(llave_privada)
        msm_descifrado = cifrador_rsa.decrypt(msj)
        return msm_descifrado
    
    # ---------> Métodos del servidor <-----------
    def recibir_msm_serv(self, client):
        while True:
            try:
                message = client.recv(1024) # recibir mensaje cifrado
                msm_descifrado = self.descifrar_msj(self.llave_priv, message) # descifrar 
                msm_claro = self.decodificar64(msm_descifrado)
                print(msm_claro) 
                msm = f"{self.nombre}: {input('')}" # El usuario escribe
                #msm_base64 = self.codificar64(msm) # codificar
                #msm_cifrado = self.cifrar_msj(key, msm_base64 ) # cifrar 
                client.send(msm.encode('utf-8')) 
            except:
                print("Error")
                client.close
                break
    
    def servidor(self): 
        self.node_serv.bind((self.ip, self.puerto_origen)) # Asignar ip y puerto

        self.node_serv.listen(5) # Esperar la conexión del cliente
        print("Servidor: " + str(self.puerto_origen) + " está escuchando")
       
        client, address = self.node_serv.accept() # Instanciar un objeto socket para aceptar la comunicación
        client.send("Conexión establecida".encode("utf-8"))

        # Intercambio de llaves 
        msm_recibido = client.recv(1024).decode('utf-8') # El objeto client recibe la llave 
        client.send(self.llave_pub) # Enviar la llave pública del servidor
       
        # Definir hilos 
        hilo_recibir = threading.Thread(target=self.recibir_msm_serv(client)) # Crear hilo para recibir y escribir
        hilo_recibir.start()

    # ---------> Métodos del cliente <-----------
    def recibir_mensages(self):
        while True:
            try:
                message = self.node_client.recv(1024).decode('utf-8') #recibir mensajes
                #msm_descifrado = self.descifrar_msj(self.llave_priv, message) # descifrar 
                #msm_claro = self.decodificar64(msm_descifrado)
                print(message) 
            except:
                print("Hay un error")
                self.node_client.close
                break

    def escribir_mensages(self, key):
        while True:
            message = f"{self.nombre}: {input('')}" # El usuario escribe
            msm_base64 = self.codificar64(message) 
            msm_cifrado = self.cifrar_msj(key, message ) 
            self.node_client.send(msm_cifrado) # El socket cliente envía el mensaje al servidor 

    def cliente(self): # Para que un usuario inicie la comunicación usa su socket cliente
        port_and_ip = (self.ip, self.puerto_destino)
        self.node_client.connect(port_and_ip) # Conectar con el servidor destino 

        message = self.node_client.recv(1024).decode('utf-8') # Recibe estado de conexión
        print(message)

        # Intercambio de llaves 
        self.node_client.send(self.llave_pub) # El cliente envía su llave pública
        key_obj1 = self.node_client.recv(1024).decode('utf-8') # Recibe la llave pública servidor 
        hilo_escribir = threading.Thread(target=self.escribir_mensages, args = (key_obj1, )) # Crear hilo para escribir 
        hilo_escribir.start()
        
        hilo_recibir = threading.Thread(target=self.recibir_mensages) # Hilo para recibir 
        hilo_recibir.start()