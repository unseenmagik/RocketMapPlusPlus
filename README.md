
# RocketMap

![Python 2.7](https://img.shields.io/badge/python-2.7-blue.svg) ![License](https://img.shields.io/github/license/RocketMap/RocketMap.svg) 

Live visualization of all the Pokémon (with option to show gyms, raids and PokéStops) in your area. This is a proof of concept that we can load all the Pokémon visible nearby given a location. Currently runs on a Flask server displaying Google Maps with markers on it. The data for these maps should come from the 'host your own map' functionality of [Pokemon Go ++](https://www.globalplusplus.com).

## Features:

* Shows Pokémon, PokéStops, raids and gyms with a clean GUI.
* Notifications
* Lure information
* Filters
* Localization (en, es, fr, pt_br, de, ru, ko, ja, zh_tw, zh_cn, zh_hk)
* DB storage (mysql) of all found Pokémon

## Installation

### Downloading the Application

To run a copy from the latest develop branch in git you can clone the repository:
`git clone --recursive https://github.com/GlobalPlusPlus/RocketMapPlusPlus.git`

### Installing Modules

At this point you should have the following:
```
Python 2.7
pip
RocketMapPlusPlus application folder
```

First, open up your shell (cmd.exe/terminal.app) and change to the directory of RocketMapPlusPlus.

You can verify your installation like this:
```
python --version
pip --version
```
The output should look something like:
```
$ python --version
Python 2.7.12
$ pip --version
pip 8.1.2 from /usr/local/lib/python2.7/site-packages (python 2.7)
```
Now you can install all the Python dependencies, make sure you’re still in the directory of RocketMapPlusPlus:

Windows:
`pip install -r requirements.txt`
Linux/OSX:
`sudo -H pip install -r requirements.txt`

### Building Front-End Assets

In order to run from a git clone, you must compile the front-end assets with node. Make sure you have node installed for your platform.
Once node/npm is installed, open a command window and validation your install:
```
node --version
npm --version
```
The output should look something like:
```
$ node --version
v4.7.0
$ npm --version
3.8.9
```
Once node/npm is installed, you can install the node dependencies and build the front-end assets:
`npm install`

The assets should automatically build (you'd see something about "grunt build"), if that doesn't happen, you can directly run the build process:
`npm run build`

### Basic Launching

Once those have run, you should be able to start using the application, make sure you’re in the directory of RocketMapPlusPlus then:
`python ./runserver.py --help`
Read through the available options and set all the required CLI flags to start your own server. At a minimum you will need to provide a location, and a google maps key.

The most basic config you could use would look something like this:
`python ./runserver.py -l "a street address or lat/lng coords here" -k "MAPS_KEY_HERE"`
Let’s run through this startup command to make sure you understand what flags are being set.

Once your setup is running, open your browser to http://localhost:5000 and your pokemon will begin to show up! Happy hunting!

### Sample config.ini example

```
gmaps-key:                     **GOOGLE MAPS KEY**
host:                          0.0.0.0
port:                          5000
location:                      48.89604,2.23689
db-host:                       **DB IP**
db-name:                       **DB NAME**
db-user:                       **DB USER**
db-pass:                       **DB PASSWORD**
gym-info
```

## ++ Integration

In order to integrate with Pokemon Go ++ you need to have your map running, make sure your iDevice can reach the map and then use the url `http://<your-ip>:<rocketmap port>/webhook` in the field 'Worker Mode URL' and enable the Worker Mode.

To let RocketMapPlusPlus decide where to scan next, fill in the url `http://<your-ip>:<rocketmap port>/scan_loc` in the field 'Location Fetch URL' and enable the Location Fetch. RocketMapPlusPlus will send your device to new locations to scan for new pokestops, gyms, raids and pokemon automatically. If you want to play manually again, disable the Location Fetch.
