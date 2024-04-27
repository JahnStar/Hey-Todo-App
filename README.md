# Serverless Todo App with Authentication

This is a simple Todo app built using Cloudflare Worker. It allows users to create, update, and view their todo items through a web interface with token-based user authentication.

## Features

* User authentication using token-based session cookies.
* Data storage in the Cloudflare Key-Value Store
* Responsive UI design with HTML templates for login and app pages
* Error handling and validation for form submissions

## How to Use

To use this Todo app, you will need to set up a Cloudflare account and configure your project as described in the [Cloudflare Workers documentation](https://developers.cloudflare.com/workers/).

To use this Todo app, follow these steps:

1. Create a KV namespace named 'EXAMPLE_TODOS' and bind it to your worker.
2. Copy the entire project into your Cloudflare Worker project using the Wrangler CLI or Quick Edit.
3. Deploy your app.
4. That's it! Your Todo app will be accessible now at `https://your-worker-name.your-subdomain.workers.dev/`.

## Demo
<div align="center">
    <a align="center" href="https://todo.jahnstar.com/" target="_blank"><strong>Click for Demo</strong></a>
    <br><br>
    <img src="./basic-todo-app.png?raw=true" width="65%">
</div>

## Contributing

Feel free to contribute to this project by forking the repository and making your desired modifications. Commit these changes with clear messages and push them to the remote repository. Finally, submit a pull request with a brief description of your contributions, helping to improve and expand the project for all users.

## License

This project is licensed under the CC-BY-4.0 License - see the [LICENSE](LICENSE) file for details.

## Credits

Developed by Halil Emre Yildiz ([GitHub](https://github.com/JahnStar))
