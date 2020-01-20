package db;

import haxe.Json;
import haxe.macro.Expr.Constant;
import js.Cookie;
import haxe.crypto.BCrypt;
import haxe.ds.Either;
import TypeDefinitions;

enum UserExistsResult {
	Yes;
	Missing;
	WrongPassword;
	Error(err:js.lib.Error);
}

enum FromTokenResult {
	User(login:String);
	Missing;
	Error(err:js.lib.Error);
}

enum DataResult {
	Result(data:Dynamic);
	Error(err:js.lib.Error);
}

class UserDataAccessor {
	static private var PEPPER:String = "RVGTJHEuubebufbyNKNUJUIE££$$$evuuiuef588451158588";

	/**
	 * Check if a user exists in database
	 * @param connection MySQLConnection The connection to the database
	 * @param uname String the username or login
	 * @param pwd 	String user password
	 * @param callback Either<js.lib.Error, Bool>->Void A callback to handle the response, response can be either a userExists information or a JavaScript error.
	 */
	public static function userExists(connection:MySQLConnection, uname:String, pwd:String, callback:UserExistsResult->Void):Void {
		connection.query("SELECT login, password FROM user WHERE login = ?", [uname], (error:js.lib.Error, results, fields) -> {
			if (error != null) {
				callback(Error(error));
				return;
			}
			if (results.length <= 0) {
				callback(Missing);
				return;
			}
			try {
				callback(BCrypt.verify(pwd + PEPPER, results[0].password) ? Yes : WrongPassword);
			} catch (e:Dynamic) {
				trace(e);
				callback(WrongPassword);
			}
		});
	}

	/**
	 * Insert a user in database.
	 * @param connection MySQLConnection The connection to the database
	 * @param user User user to insert
	 * @param callback Either<js.lib.Error, Bool>->Void A callback to handle the response, response can be either the "user is in database" information or a JavaScript error.
	 */
	public static function createUser(connection:MySQLConnection, user:User, callback:Either<js.lib.Error, Bool>->Void) {
		var newPassword = BCrypt.encode(user.password + PEPPER, BCrypt.generateSalt());
		connection.query("INSERT INTO user(login, password)  VALUES(?,?)", [user.login, newPassword], (error:js.lib.Error, results, fields) -> {
			if (error != null) {
				callback(Left(error));
				return;
			}
			callback(Right(true));
		});
	}

	public static function createToken(connection:MySQLConnection, login:String, durationInMinutes:Float = 0, callback:Either<js.lib.Error, String>->Void) {
		var token = BCrypt.generateSalt(10, BCrypt.Revision2B);
		var dayInMs:Float = 24 * 60 * 60 * 1000;
		connection.query("INSERT INTO token(id, id_user, expiration) VALUES(?,?,?)", [token, login, dayInMs], (error:js.lib.Error, results, fields) -> {
			if (error != null) {
				callback(Left(error));
				return;
			}
			callback(Right(token));
		});
	}

	public static function fromToken(connection:MySQLConnection, token:String, callback:FromTokenResult->Void):Void {
		connection.query("SELECT user.login, token.expiration FROM user INNER JOIN token ON user.login = token.id_user WHERE token.id = ?", [token],
			(error:js.lib.Error, results, fields) -> {
				if (error != null) {
					callback(Error(error));
					return;
				}
				if (results.length <= 0) {
					callback(Missing);
					return;
				}
				callback(User(results[0].login));
			});
	}

	public static function save(connection:MySQLConnection, login:String, data:Dynamic, callback:DataResult->Void):Void {
		connection.query("UPDATE user SET data = ? WHERE login = ?", [Json.stringify(data), login], (error:js.lib.Error, results, fields) -> {
			if (error != null) {
				callback(Error(error));
				return;
			}
			callback(Result(results));
		});
	}

	public static function load(connection:MySQLConnection, login:String, callback:DataResult->Void):Void {
		connection.query("SELECT data FROM user WHERE login = ? ", [login], (error:js.lib.Error, results, fields) -> {
			if (error != null) {
				callback(Error(error));
				return;
			}
			callback(Result(results[0].data));
		});
	}
}
