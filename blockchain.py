import json
import hashlib
import requests
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from flask import Flask, jsonify, request


class Blockchain:
    def __init__(self):
        self.next_block_transactions = []
        self.chain = []
        self.node_set = set()

        # Создаёт генезисный блок
        self.new_block(previous_hash='1', proof=100)

    def add_node(self, address):
        """
        Добавляет ноду во множество нод

        Параметр address: Адрес ноды, например 'http://192.168.0.34:10000'
        """

        ready_url = urlparse(address)
        if ready_url.netloc:
            self.node_set.add(ready_url.netloc)
        elif ready_url.path:
            # Принимает URL без схемы, как, например, '192.168.0.34:10000'.
            self.node_set.add(ready_url.path)
        else:
            raise ValueError('Incorrect address')

    def new_block(self, proof, previous_hash, extern_time=0):
        """
        Создаёт новый блок в блокчейне


        Параметр proof: Доказательство(пруф), данное алгоритмом доказательства работы
        Параметр previous_hash: Хэш предыдущего блока
        Параметр extern_time: Передаётся в случае вызова функции другой нодой при добавлении созданного ею блока
        Возвращает новый блок
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': extern_time if extern_time > 0 else time(),
            'transactions': self.next_block_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Очищает список последних транзакций
        self.next_block_transactions = []

        self.chain.append(block)
        return block


    def is_chain_valid(self, chain):
        """
        Определяет, валидна ли цепь

        Параметр chain: Сама цепь блоков - блокчейн
        Возвращает истину, если валидна, иначе ложь
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Проверяет корректность хэша блока
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Проверяет доказательство работы
            if not self.verify_proof_of_work(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        Это алгоритм консенсуса, он разрешает конфликты, заменяя цепь
        самой длинной цепью в сети

        Возвращает истину, если цепь была заменена, иначе ложь
        """

        neighbours = self.node_set
        new_chain = None

        # Мы ищем только цепи длиннее нашей
        max_length = len(self.chain)

        # Проверяем цепи со всех нод в нашей сети
        for node in neighbours:
            response = requests.get(f'http://{node}:10000/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Проверяем, валидна ли цепь и больше ли она, чем наша
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    new_chain = chain

        # Заменяем нашу цепь, если нашли другую большую и валидную
        if new_chain:
            self.chain = new_chain
            return True

        return False

    
    def new_transaction(self, payer, payee, quantity, extern_time):
        """
        Создаёт новую транзакцию, которая войдёт в следующий созданный блок

        Параметр payer: Адрес отправителя
        Параметр payee: Адрес получателя
        Параметр quantity: Количество
        Возвращает индекс блока, в котором будет находиться данная транзакция
        """
        self.next_block_transactions.append({
            'payer' : payer,
            'payee' : payee,
            'quantity' : quantity,
            'timestamp' : extern_time,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        #Возвращает последний блок в цепи
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Создаёт SHA-256 хэш блока

        Параметр block: Блок, хэш которого будет создан
        """

        # Мы должны быть уверены, что словарь упорядочен, иначе хэши будут противоречивыми
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Алгоритм доказательства работы(proof of work):

         - Ищет число p' такое, что hash(pp') содержит 4 ведущих цифры семь
         - Где p это предыдущий пруф, и p' это новый пруф
         
        Параметр last_block: <dict> Последний сформированный блок из цепи
        Возвращает найденное целочисленное доказательство работы
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.verify_proof_of_work(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def verify_proof_of_work(last_proof, proof, last_hash):
        """
        Проверка доказательства(пруфа)

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        probe = f'{last_proof}{proof}{last_hash}'.encode()
        probe_hash = hashlib.sha256(probe).hexdigest()
        return probe_hash[:4] == "7777"


# Инициализируем ноду
app = Flask(__name__)

# Создаём глобальный уникальный адресс для этой ноды
node_identifier = str(uuid4()).replace('-', '')

# Создаём экземпляр класса Blockchain
blockchain = Blockchain()


@app.route('/chain', methods=['GET'])
def whole_chain():
    
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/chain/addblock', methods=['POST'])
def add_block():
    '''
    Проверяет хэш полученного блока и в случае его корректности
    добавляет блок в цепь
    '''
    block = request.get_json(force=True)
    blockchain.next_block_transactions = block['transactions']
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    last_hash = blockchain.hash(last_block)
    if blockchain.verify_proof_of_work(last_proof, block['proof'], last_hash):
        blockchain.new_block(block['proof'], last_hash, block['timestamp'])
        nodes_without_sender = list(blockchain.node_set.difference(request.remote_addr))
        for node in nodes_without_sender:
            requests.post(f'http://{node}:10000/chain/addblock', json=block)
        return jsonify({"message" : "Block is ok, i'll add it to my stock"}), 201
    else:
        if blockchain.resolve_conflicts():
            return jsonify({"message" : "The chain was replaced"}), 201
        else:
            return jsonify({"message" : "Invalid block"}), 400


@app.route('/chain/mine', methods=['GET'])
def mine():
    # Мы запускаем алгоритм доказательства работы, чтобы получить следующее доказательство...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # Мы должны получить награду за нахождение доказательства.
    # Значение поля payer равное "0" означает, что данная нода создала блок.
    blockchain.new_transaction(
        payer="0",
        payee=node_identifier,
        quantity=1,
        extern_time=time()
    )

    # Создаём новый блок, добавляя его в цепь
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    #Рассылает готовый блок всем известным узлам(нодам)
    node_list = list(blockchain.node_set)
    for node in node_list:
            requests.post(f'http://{node}:10000/chain/addblock', json=block)

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def create_transaction():
    req_input = request.get_json(force=True)

    # Проверяем, что требуемые поля существуют в теле POST запроса
    required = ['payer', 'payee', 'quantity']
    if not all(k in req_input for k in required):
        return 'Missing values', 400
    transaction = {'payer' : req_input['payer'], 'payee' : req_input['payee'], 'quantity' : req_input['quantity'], 'timestamp' : time()}
    # Создаём новую транзакцию
    index = blockchain.new_transaction(transaction['payer'], transaction['payee'], transaction['quantity'], transaction['timestamp'])

    # Рассылаем созданную транзакцию всем известным нодам
    node_list = list(blockchain.node_set)
    for node in node_list:
            requests.post(f'http://{node}:10000/transactions/add', json=transaction)

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/transactions/add', methods=['POST'])
def add_transaction():
    #Вызванная другой нодой, добавляет транзакцию в список неподтверждённых транзакций
    req_input = request.get_json(force=True)
    required = ['payer', 'payee', 'quantity', 'timestamp']
    if not all(k in req_input for k in required):
        return 'Missing values', 400
    if req_input not in blockchain.next_block_transactions:
        index = blockchain.new_transaction(req_input['payer'], req_input['payee'], req_input['quantity'], req_input['timestamp'])
        nodes_without_sender = list(blockchain.node_set.difference(request.remote_addr))
        for node in nodes_without_sender:
            requests.post(f'http://{node}:10000/transactions/add', json=req_input)
        response = {'message': f'Transaction was added to Block {index}'}
        return jsonify(response), 201
    else:
        return jsonify({'message' : 'Transactions has already added'}), 200

@app.route('/transactions/list', methods =['GET'])
def list_transactions():
    #Отображает множество неподтверждённых транзакций
    response = {
        'transactions' : blockchain.next_block_transactions
    }
    return jsonify(response), 200
   

@app.route('/nodes/list', methods=['GET'])
def list_nodes():
    #Отображает список известных данному узлу нод
    nodes_list = list(blockchain.node_set)
    response = {}
    if len(nodes_list) is 0:
        response = {
            'message': 'You are the only one',
        }
    else:
        response = {
            'nodes' : nodes_list
        }
    return jsonify(response), 200


@app.route('/nodes/add', methods=['POST'])
def add_nodes():
    #Добавляет определённый узел в список известных нод
    req_input = request.get_json(force=True)

    nodes = req_input.get('nodes')
    if nodes is None:
        return "Error: Incorrect list of nodes", 400

    for node in nodes:
        blockchain.add_node(node)

    requests.post(f'http://{node}:10000/nodes/add-me')

    #Вызывает алгоритм разрешения конфликтов для избежания конфликтов при встраивании в сеть
    blockchain.resolve_conflicts()

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.node_set),
    }
    return jsonify(response), 201


@app.route('/nodes/add-me', methods=['POST'])
def add_requester():
    '''
    Проверяет, не является ли запрашивающий локалхостом и, 
    если его нет во множестве нод, добавляет его
    '''
    if request.remote_addr not in blockchain.node_set and request.remote_addr != "127.0.0.1":
        blockchain.add_node(request.remote_addr)

    return jsonify({"message" : "You have been added"}), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    '''
    Вызывает алгоритм консенсуса для избежания конфликтов
    
    Необходимо периодически проводить эту процедуру, чтобы предотвратить разветвление(форк) цепи
    '''
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
