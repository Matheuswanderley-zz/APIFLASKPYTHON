from flask_restful import Resource, reqparse
from models import UserModel, RevokedTokenModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required,
                                get_jwt_identity, get_raw_jwt)


parser = reqparse.RequestParser()
parser.add_argument('name', type=str, help='Este campo nao pode ser vazio', required=True)
parser.add_argument('email', type=str, help='Este campo nao pode ser vazio', required=True)
parser.add_argument('password', type=str, help='Este campo nao pode ser vazio', required=True)
parser.add_argument('cel', type=str, help='Este campo nao pode ser vazio')
parser.add_argument('code_state', type=str, help='Este campo nao pode ser vazio')


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_email(data['email']):
            return {'Message': 'Usuario {} ja existe.'.format(data['email'])}

        new_user = UserModel(
            name=data['name'],
            email=data['email'],
            password=UserModel.generate_hash(data['password']),
            cel=data['cel'],
            code_state=data['code_state']
        )
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['email'])
            refresh_token = create_refresh_token(identity=data['email'])
            return {
                'message': 'O Usuario {} foi criado'.format(data['email']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Ooops Algo deu Errado'}, 500


class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_email(data['email'])
        if not current_user:
            return {'Message': 'Usuario {} nao Existe'}.format(data['email'])

        if UserModel.generate_hash(data['password']) == current_user.password:
            access_token = create_refresh_token(identity=data['email']),
            refresh_token = create_refresh_token(identity=data['email'])
            return {'Message': 'Logado como {}'.format(current_user.email),
                    'access_token': access_token,
                    'refresh_token': refresh_token
             }
        else:
            return {'Message': 'Senha incorreta'}


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Token de acesso revogado'}
        except:
            return {'message': 'Ooops algo deu errado'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Token Revogado'}
        except:
            return {'message': 'Ooops Algo deu errado'}, 500



class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        acces_token = create_access_token(identity=current_user)
        return {'access_token': acces_token}


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }
