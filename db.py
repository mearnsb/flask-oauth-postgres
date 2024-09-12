import sqlite3
import os
import click
from flask import current_app, g
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import psycopg2.pool

def get_db():
    
    if "db" not in g:    
        connection = psycopg2.connect(
        user = os.environ.get("POSTGRES_USER"),
        password = os.environ.get("POSTGRES_PASSWORD"),
        host = "aws-0-us-east-1.pooler.supabase.com",
        port = "5432",
        database = "postgres")
       
        #g.db = connection
        #g.db.row_factory = sqlite3.Row
        g.db = connection
      
    return g.db

def close_db(e=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    q = ""
    try:
        with current_app.open_resource("schema.sql") as f:
            #db.executescript(f.read().decode("utf8"))
                q = f.read().decode("utf8")
    
        cursor.execute(q)
    except Exception as e: 
        print(e)
        
@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)