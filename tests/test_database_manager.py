from app.database_manager import _engine_from_image, _is_write_sql, _literal
from app.platform import app


def test_database_engine_detection_covers_supported_images() -> None:
    assert _engine_from_image("postgres:16-alpine") == "postgresql"
    assert _engine_from_image("postgis/postgis:16-3.4") == "postgresql"
    assert _engine_from_image("mariadb:11") == "mariadb"
    assert _engine_from_image("mysql:8.4") == "mysql"
    assert _engine_from_image("redis:7") is None


def test_sql_console_requires_confirmation_for_write_capable_sql() -> None:
    assert _is_write_sql("SELECT * FROM clients") is False
    assert _is_write_sql("-- comment\nSELECT 1") is False
    assert _is_write_sql("SHOW TABLES") is False
    assert _is_write_sql("UPDATE clients SET active=false") is True
    assert _is_write_sql("DROP TABLE clients") is True
    # WITH can contain data-changing CTEs, so keep it conservative.
    assert _is_write_sql("WITH x AS (SELECT 1) SELECT * FROM x") is True


def test_sql_literals_escape_quotes_and_nulls() -> None:
    assert _literal(None, "postgresql") == "NULL"
    assert _literal(True, "postgresql") == "TRUE"
    assert _literal(42, "mysql") == "42"
    assert _literal("O'Reilly", "postgresql") == "'O''Reilly'"


def test_database_manager_routes_are_registered() -> None:
    paths = {getattr(route, "path", "") for route in app.router.routes}
    expected = {
        "/vps/{server_id}/databases",
        "/api/vps/servers/{server_id}/databases/instances",
        "/api/vps/servers/{server_id}/databases/catalog",
        "/api/vps/servers/{server_id}/databases/tables",
        "/api/vps/servers/{server_id}/databases/table",
        "/api/vps/servers/{server_id}/databases/roles",
        "/api/vps/servers/{server_id}/databases/sql",
        "/api/vps/servers/{server_id}/databases/backup",
        "/api/vps/servers/{server_id}/databases/restore",
    }
    assert expected.issubset(paths)
