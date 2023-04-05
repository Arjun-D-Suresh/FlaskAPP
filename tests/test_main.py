import pytest
from FlaskApp.main import db, Users, app, Entries


ENDPOINT = "http://127.0.0.1:5000/"

add_entry_json = {
        'native_english_speaker': True,
        'course_instructor': 13,
        'course': 21,
        'summer_semester': False,
        'class_size': 50,
        'score': 1
    }

update_entry_json = {
        "native_english_speaker": True,
        "course_instructor": 14,
        "course": 18,
        "summer_semester": False,
        "class_size": 37,
        "score": 3
}


@pytest.fixture(scope='session')
def application():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    with app.app_context():
        db.create_all()
        yield app


@pytest.fixture(scope='function')
def client(application):
    with app.app_context():
        with app.test_client() as client:
            yield client


def test_create_user(client):
    response = client.post('/create_user', json={'username': 'te', 'password': 'test'})
    assert response.json['status_code'] == 400
    response = client.post('/create_user', json={'username': 'testuser', 'password': 'testpassword'})
    assert response.json['status_code'] == 201
    user = Users.query.filter_by(username='testuser').first()
    assert user is not None


def test_crud_endpoints(client):

    wrong_login_response = client.post('/login', json={'username': 'testuser', 'password': 'testpassword123'})
    assert wrong_login_response.json["status_code"] == 401

    correct_login_response = client.post('/login', json={'username': 'testuser', 'password': 'testpassword'})
    assert correct_login_response.json["status_code"] == 200

    jwt_token = correct_login_response.json["token"]
    assert jwt_token is not None

    add_entry_response = client.post('/add_entry', json=add_entry_json,
                                     headers={'Authorization': f'Bearer {jwt_token}'})
    assert add_entry_response.json["status_code"] == 201

    get_entry_response = client.get("/entries", headers={'Authorization': f'Bearer {jwt_token}'})
    assert get_entry_response.json is not None

    entry_id = get_entry_response.json[-1]["id"]
    assert entry_id is not None

    update_entry_response = client.put(f"/update_entry/{entry_id}", json=update_entry_json,
                                       headers={'Authorization': f'Bearer {jwt_token}'})
    assert update_entry_response.json["status_code"] == 204

    wrong_update_entry_response = client.put(f"/update_entry/99", json=update_entry_json,
                                       headers={'Authorization': f'Bearer {jwt_token}'})
    assert wrong_update_entry_response.json["status_code"] == 401 or 404

    delete_entry_response = client.delete(f"/delete_entry/{entry_id}",
                                          headers={'Authorization': f'Bearer {jwt_token}'})
    assert delete_entry_response.json["status_code"] == 204
    deleted_entry = Entries.query.filter(Entries.id == entry_id).first()
    assert not deleted_entry

    delete_user_response = client.delete("/delete_user", headers={'Authorization': f'Bearer {jwt_token}'})
    assert delete_user_response.json["status_code"] == 204




