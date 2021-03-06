import js.npm.express.Request;

/**
 * Application data model
 */
typedef User = {
	var login:String;
	var password:String;
}

typedef Token = {
	var id:String;
	var user_id:String;
	var expiration:Date;
}

/**
 * Mysql externs for npm package "mysql"
 * See documentation at https://github.com/mysqljs/mysql
 * Those types are extrapolated (deduced) from usages seen on the documentation.
 */
typedef MySQLConfig = {
	?host:String,
	?port:Int,
	?user:String,
	?password:String,
	database:String
}

typedef MySQL = {
	createConnection:Dynamic->MySQLConnection,
	format:String->Array<String>->Dynamic
}

typedef MySQLConnection = {
	connect:Void->Void,
	changeUser:Dynamic->(Dynamic->Void)->Void,
	escape:String->String,
	escapeId:String->String,
	pause:(Dynamic->Void)->Void,
	end:Void->Void,
	query:String->?Array<Dynamic>->?(Dynamic->Array<Dynamic>->Array<Dynamic>->Void)->Dynamic
}
