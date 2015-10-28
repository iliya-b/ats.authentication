
from ats.util.db import sql


async def insert_jwt(dbh, token, uid, issued_at, expires_at):
    await sql(dbh, """
        INSERT INTO jwt (
            token, uid, issued_at, expires_at, is_revoked
        )
        VALUES (%s, %s, %s, %s, 0)
        """, [token, uid, issued_at, expires_at])


async def revoke_jwt(dbh, token):
    await sql(dbh, """
           UPDATE jwt
               SET is_revoked=1
             WHERE token = %s
        """, [token])


async def revoke_all_jwt(dbh, userid):
    await sql(dbh, """
           UPDATE jwt
               SET is_revoked=1
             WHERE uid = %s
        """, [userid])
