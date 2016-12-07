# Project: Item Catalog

This is a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication. The Item Catalog project consists of developing an application that provides a list of items within a variety of categories, as well as provide a user registration and authentication system.


## Installation
1. Python
2. VirtualBox
3. Vagrant
4. Git


## Steps:
1. Install Vagrant and VirtualBox
2. Clone the fullstack-nanodegree-vm repository :
  - Run: `git clone http://github.com/udacity/fullstack-nanodegree-vm fullstack`
4. Move to the *vagrant* folder : `cd fullstack/vagrant/`
5. Using Git, clone this project:
  - Run: `git clone https://github.com/eunbigo91/project5-item-catalog.git catalog`
  - This will create a directory inside the *vagrant* directory titled *catalog*.
6. Powers on the virtual machine : `vagrant up`
7. Logs into the virtual machine : `vagrant ssh`
8. Change directory to the synced folders : `cd /vagrant/catalog`
9. Set up the database : python database_setup.py
10. Run project.py : python application.py
11. Access and test your application by visiting : http://localhost:8000 locally


## JSON API endpoints
- `http://localhost:8000/catalog/JSON` or `http://localhost:8000/catalog/category.json` : lists all the items in the database by categories
- `http://localhost:8000/catalog/category/JSON` or `http://localhost:8000/catalog/category.json`: lists all the categories
- `http://localhost:8000/catalog/allitems/JSON` or `http://localhost:8000/catalog/allitems.json`: lists all the items in the database
- `http://localhost:8000/catalog/<string:category_name>/JSON` or `http://localhost:8000/catalog/<string:category_name>.json`: lists all the items in the specific categroy


## Copyright and License
- Project starter code contributed by Udacity Full Stack Web Developer Nanodegree Program.
- Additional code contributed by Eunbi Go.



