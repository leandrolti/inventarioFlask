# adicionar_serie.py
from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Comando para adicionar a coluna num_serie
        db.session.execute(text('ALTER TABLE ativo ADD COLUMN num_serie VARCHAR(100)'))
        db.session.commit()
        print("Coluna 'num_serie' adicionada com sucesso!")
    except Exception as e:
        print("Erro ou coluna já existente:", e)