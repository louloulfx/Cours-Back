import haxe.crypto.BCrypt;
import db.UserDataAccessor;
import js.Node;
import js.npm.express.Request;
import js.npm.express.Response;
import js.npm.Express;
import js.npm.express.BodyParser;
import js.npm.express.Session;
import TypeDefinitions;
import js.npm.ws.WebSocket;
import js.npm.ws.Server as WSServer;

extern class RequestWithSession extends Request {
	public var session:{token:String};
}

extern class RequestLogin extends RequestWithSession {
	public var body:{login:String, password:String, id:String};
}

extern class RequestSubscribe extends RequestWithSession {
	public var body:{
		id:String,
		login:String,
		password:String
	};
}

extern class RequestData extends RequestWithSession {
	public var body:Dynamic;
}

class Main {
	static var db(default, never):MySQL = Node.require("mysql");

	static var sockets:List<WebSocket> = new List<WebSocket>();

	static var tickets:Map<String, String> = new Map<String, String>();

	static function main() {
		Node.require('dotenv').config();

		var connection = db.createConnection({
			host: Sys.getEnv("DB_host"),
			user: Sys.getEnv("DB_user"),
			password: Sys.getEnv("DB_password"),
			database: Sys.getEnv("DB_database")
		});

		connection.connect();

		// Setup express server with middlewares
		var server:Express = new js.npm.Express();
		server.use(BodyParser.json({limit: '5mb', type: 'application/json'}));
		server.use(new Session({
			secret: 'shhhh, very secret',
			resave: true,
			saveUninitialized: true
		}));

		var wss = new WSServer({
			port: 1338
		});

		wss.on('connection', function(socket:WebSocket) {
			sockets.add(socket);

			socket.on('close', function() {
				sockets.remove(socket);
				for (s in sockets) {
					s.send("A friend disconnected !", null);
				}
			});

			socket.on('message', function(msg:Dynamic) {
				for (s in sockets) {
					s.send(Std.string(msg), null);
				}
			});
		});

		server.get('/random', function(req:Request, res:Response) {
			res.writeHead(200, {'Content-Type': 'text/plain'});
			res.end(Std.string(Math.random()));
		});

		server.post('/login', function(expressReq:Request, res:Response) {
			var req:RequestLogin = cast(expressReq);
			switch (req.body) {
				case {login: login, password: password}
					if (login == null || password == null):
					// username and password must be provided
					req.session.token = null;
					res.send(400, "Bad Request");
				case {login: login, password: password, id: id}:
					UserDataAccessor.userExists(connection, login, password, result -> switch (result) {
						case UserExistsResult.Error(err):
							trace(err);
							res.send(500, err.message);
						case UserExistsResult.Yes:
							UserDataAccessor.createToken(connection, login, 0, createTokenResult -> switch createTokenResult {
								case Right(token):
									req.session.token = token;
									res.send(200, "OK");
								case Left(err):
									trace(err);
									res.send(500, err.message);
							});
						case UserExistsResult.Missing | UserExistsResult.WrongPassword:
							req.session.token = null;
							res.send(401, "Unauthorized");
					});
			}
		});

		server.post('/save', function(expressReq:Request, res:Response) {
			var req:RequestData = cast(expressReq);
			if (req.session.token == null) {
				res.send(401, "Mauvais token");
				return;
			}
			UserDataAccessor.fromToken(connection, req.session.token, result -> switch (result) {
				case User(login):
					UserDataAccessor.save(connection, login, req.body, result -> switch (result) {
						case Result(_):
							res.send(200, "OK");
						case Error(err):
							res.send(500, err);
					});
				case Missing:
					res.send(401, 'Mauvais token');
				case Error(err):
					res.send(500, err);
			});
		});

		server.post('/load', function(expressReq:Request, res:Response) {
			var req:RequestData = cast(expressReq);
			if (req.session.token == null) {
				res.send(401, "Mauvais token");
				return;
			}
			UserDataAccessor.fromToken(connection, req.session.token, result -> switch (result) {
				case User(login):
					UserDataAccessor.load(connection, login, result -> switch (result) {
						case Result(data):
							res.send(200, data);
						case Error(err):
							res.send(500, err);
					});
				case Missing:
					res.send(401, 'Mauvais token');
				case Error(err):
					res.send(500, err);
			});
		});

		server.get('/wsTicket', function(expressReq:Request, res:Response) {
			var req:RequestData = cast(expressReq);
			if (req.session.token == null) {
				res.send(401, "Mauvais token");
				return;
			}
			UserDataAccessor.fromToken(connection, req.session.token, result -> switch (result) {
				case User(login):
					var ticket = BCrypt.generateSalt(10, BCrypt.Revision2B);
					tickets[ticket] = login;
					res.send(200, ticket);
				case Missing:
					res.send(401, 'Mauvais token');
				case Error(err):
					res.send(500, err);
			});
		});

		server.post('/subscribe', function(expressReq:Request, res:Response) {
			var req:RequestSubscribe = cast(expressReq);

			switch (req.body) {
				case {login: login, password: password}
					if (login == null || password == null):
					// username and password and email must be provided
					res.send(400, "Bad Request");
				case {
					login: login,
					password: password
				}:
					UserDataAccessor.userExists(connection, login, password, result -> switch (result) {
						case UserExistsResult.Error(err):
							trace(err);
							res.send(500, err.message);
						case UserExistsResult.Yes, UserExistsResult.WrongPassword:
							res.send(500, "User already exists, please use another login");
						case UserExistsResult.Missing:
							UserDataAccessor.createUser(connection, {
								login: login,
								password: password,
							}, response -> switch (response) {
								case Left(err):
									res.send(500, "An error occured\n" + err.message);
								case Right(_):
									res.send(200, "OK");
							});
					});
			}
		});

		server.post('/logout', function(expressReq:Request, res:Response) {
			var req:RequestWithSession = cast(expressReq);
			req.session.token = null;
			res.send(200, "OK");
			return;
		});

		server.get('/status', function(expressReq:Request, res:Response) {
			var req:RequestWithSession = cast(expressReq);
			trace(req.session.token);
			if (req.session.token == null) {
				res.send(200, "Visiteur");
				return;
			}
			UserDataAccessor.fromToken(connection, req.session.token, result -> switch (result) {
				case User(login):
					res.send(200, "Bonjour " + login);
				case Missing:
					res.send(401, "Token invalide. Vous devez vous re-connecter.");
				case Error(err):
					res.send(500, err);
			});
		});

		var port = 1337;
		if (Sys.getEnv("PORT") != null) {
			port = Std.parseInt(Sys.getEnv("PORT"));
		}
		server.listen(port, '127.0.0.1');
		trace('Server running at http://127.0.0.1:${port}/');
		Node.process.on('SIGTERM', function onSigterm() {
			trace('Got SIGTERM. Graceful shutdown start');
			connection.end();
		});
	}
}
