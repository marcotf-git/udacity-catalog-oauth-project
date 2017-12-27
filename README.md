# Item Catalog Application

This project is an exercise as part of the **Full Stack Web Developer Nanodegree**, by **Udacity**. It is a web application that provides a list of items within a variety of categories and integrate third-party user registration and authentication, besides the possibility of local authentication.

It is possible to create a list of categories, and for each one, to register a list of items, with the name of the item and the description. The project also register the owner of that item, or of that category, so only the owner can edit or delete it. The categories can be created or deleted by the owner, but for that, the category must also be empty.

The program uses **SQLAlchemy** (<https://www.sqlalchemy.org/>) to make CRUD operations in the database `catalog.db`.

It also uses **Flask** (<http://flask.pocoo.org/>) framework to map the routes, to render the templates, to extract data from forms, and to control the session, mainly.

There is the option to authenticate the users with third-party authentication  **OAuth2** protocol. The program uses the Google provider (that uses a mixed protocol)(<https://developers.google.com/identity/protocols/OAuth2>).

For local authentication, it is recommended a secure https connection, but this part of the project (the setup for the https connection at the server side) is not yet implemented. For testing and learning purposes, the project works with the http protocol for the local authentication.


# Installation

* The project makes use of a Linux-based virtual machine (VM). To install this machine, please:

  1. Install **VirtualBox**: <https://www.virtualbox.org/wiki/Download_Old_Builds_5_1>
  2. Install **Vagrant** (for automated building the VM according with some set of configurations): <https://www.vagrantup.com/>
  3. Make a directory at local machine, for the project;
  4. Download the file `Vagrantfile`, that is a configuration file for the VM, created by **Udacity** for the course (this file will be accessed by the **Vagrant** to build the VM):
  <https://github.com/udacity/fullstack-nanodegree-vm>
  5. Put the file `Vagrantfile` in the local directory that you created for the project;
  6. With a **Git Bash** terminal, go to that directory (where the `Vagrantfile` is) and command `vagrant up`.

* The `vagrant` directory is automatically installed by **Vagrant** as a shared directory between the local machine and the VM. So, it is easy to share files between them.

* You need to copy the **Python** files `database_setup.py`, `make_items.py` and `project.py`, supplied with this project, to a directory at the remote machine, that will be the "server". Also copy the `static` and `template` folders to the same folder. As the `vagrant` directory is automatically shared, copy the files to your local `vagrant` directory, and access these files by connection with **ssh** the remote server:

  - use a **Git Bash** shell (if you are in **Windows**)
  - with that shell, go to the `\vagrant` directory that was previously created when installing the `vagrant` virtual machine
  - run the virtual machine with `vagrant up` command
  - open a remote terminal with the `vagrant ssh` command
  - in remote machine, using the terminal, go to the `\vagrant` directory
  - check to see if the files are there

* Setting up the database:

  - in remote machine, run the python code with `python database_setup.py`
  - the `database-setup.py` contains the `schema` of the database
  - You can run also `python make_items.py` for populate the database with initial items for testing purposes

* Setting up the `CLIENT ID` for use with the **OAuth2** protocol:

  - You need to go for this link <https://developers.google.com/identity/protocols/OAuth2> and follow the instructions to register the application at the Google Developer Console
  - after that, download the file `client_secrets.json` (rename to give this exact name) and save at the same folder of the project
  - this will make the third-party authentication (via Google authentication) works for the project

* Setting up the webserver port:

  - at the final of `project.py`, there is a line where shows the `port=8000` inside the **Flask** `run` method. It is the server port. For more instructions, see the link <http://flask.pocoo.org/docs/0.12/quickstart/>


# Common usage

* After running the program with the `python project.py` command, it is possible to access the app by typing the <http://localhost:8000/> in your local browser.

* There it will be possible to create "categories" and "items", but the user must be logged first. It is also possible to edit and delete the items or categories, but only for that logged user who initially created the item or category(the "owner" of it). The categories can only be edited or deleted if they are empty.

* At any moment, go to the home page by clicking the **Catalog App** at the top. At that page, there are links for adding categories and items. Clicking at the category, opens a new page showing the items. At that page, there are links for editing and deleting the items, for the users who created them.

* It is possible for every logged user to edit or delete a category, but must be logged.

* It is also possible to everyone (not logged) to obtain a list of categories and items by a **JSON** query to the app, by typing <http://localhost:8000/catalog.json>.

* The login method can be made by two forms: third-party authentication (the user password is stored with the service that hosts the user account) and local
authentication (the password is stored by the app, in its database). In case of local authentication, it is possible to user locally create an `user`, registering the `username`, `e-mail` and `password`. After that, it is possible to login with the `username` or with the `e-mail`.

* This app is for learning purposes. :books:


# Known issues

* This app was tested with the Google Chrome (v.63) and with the Internet Explorer 11. It seems, until the moment, it doesn't work with the Microsoft Edge (v.41), when trying to make the third-party authentication.
