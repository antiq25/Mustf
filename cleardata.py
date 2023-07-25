from app import app, db

def clear_data(session):
    meta = db.metadata
    for table in reversed(meta.sorted_tables):
        print ('Clear table %s' % table)
        with app.app_context():
         session.execute(table.delete())
         session.commit()

