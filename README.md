# TinFlect Shop - Host your own TinFoil store and manage your games!


![Logo](https://i.imgur.com/X6u5b1a.png)

This project is a comprehensive, web-based administration panel for managing a self-hosted Tinfoil server. It provides a user-friendly interface to control users, manage the game library, monitor server activity, and configure the core Tinfoil server process.

---

## 🌐 Supported Languages:

![English](https://img.shields.io/badge/English-blue) ![Português (Brasil)](https://img.shields.io/badge/Portugu%C3%AAs%20(Brasil)-green) ![Español](https://img.shields.io/badge/Espa%C3%B1ol-orange) ![Русский](https://img.shields.io/badge/Русский-red) ![中文](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-purple)

---

## Key Features

* **Dashboard Overview**: A central hub to monitor server status, view shop statistics, and access quick actions.
* **Real-time & Stored Logging**: A live log stream for immediate feedback and a searchable database for historical events.
* **Full User Management**: Create, delete, ban, unban, and manage passwords for users accessing the shop.
* **Download Quota Control**: Track daily downloads per user and manually reset quotas.
* **Automated Library Scanner (Watcher)**: Automatically detect and add new game files by monitoring specified directories.
* **Comprehensive Game Library**: Browse a master list of games, filter by category or publisher, and see which titles are available in your local shop.
* **Detailed Game View**: See in-depth information for each game, including metadata, descriptions, screenshots, and the availability of related updates and DLCs.
* **Server Configuration**: Easily change core settings like the shop title, network port, and public-facing URL directly from the UI.
* **Customizable Tinfoil Messages**: Edit the messages displayed within the Tinfoil application, using dynamic placeholders for a personalized experience.

---

## `prod.keys` File Requirement
![Library](https://i.imgur.com/oTkA3Dn.png)

For the File Watcher service to function correctly, a `prod.keys` file is required. This file contains the necessary keys to decrypt and parse metadata from game files such as `.nsp`, `.nsz`, `.xci`, and `.xcz`. Without a valid `prod.keys` file, the watcher's validation and metadata reading functions will not work, and it will be unable to add new content to your library database.

This file must be obtained by you. It can typically be dumped from your own console or found through various sources online.

**Disclaimer**: We do not provide, link to, or offer any instructions on how to acquire the `prod.keys` file. You are responsible for sourcing this file yourself.

## Admin Panel Sections

### 1. Login
A secure portal for administrative access to the panel.

A unique password is generated on the first run; you'll find it at the run prompt. You must change the password in "manage profiles." If you haven't saved your password, delete the db/users.db file and restart the system.

![login](https://i.imgur.com/S1Yk6Uu.png)

### 2. Dashboard
![dashboard](https://i.imgur.com/yKkPj77.jpeg)

The main landing page after logging in, providing an at-a-glance overview of the system.

* **Server Status**: Shows whether the core "Shop Core" is `Online` or `Offline` and displays the network port and public address Tinfoil should connect to.
* **Shop Summary**: Displays key metrics, including the total number of registered users, the number of games in the library, and a count of log entries generated during the current session.
* **Quick Actions**: Provides buttons for common tasks:
    * Manage Users
    * Restart Tinfoil Server
    * Start/Stop Tinfoil Server
* **Real-time Log**: A live-updating terminal window that streams log events from all parts of the application (Core, Watcher, Admin, System). It includes features to filter by log level and source, search messages, and clear the view.
* **Recent Log Files**: Lists recently created physical log files, with options to view their contents.

### 3. Profile Management

This section is split into two tabs for comprehensive user and download management.

* **Registered Users Tab**:
![registered users](https://i.imgur.com/0WTRtRW.png)

    * Lists all registered users with their ID, name, UID link status, and creation date.
    * Provides actions to change a user's password, ban/unban them, and delete them (except for the admin user, ID 1).
    * Users with a linked UID show a "Linked" status, which can be clicked to expand and view the full device UID.
    * Includes filters to search for users by name or by their UID link status ("Linked" or "Not linked").

* **User Downloads Tab**:
![registered users](https://i.imgur.com/bWCrH23.png)

    * Displays a list of users with linked UIDs to manage their daily download quotas.
    * Shows the number of downloads a user has made for the current day.
    * Provides tools to "Clear daily quota" for a user or view "Details" of their downloads for the day in a modal window.

### 4. Game Library
A browsable interface for the entire TitleDB, showing the status of your local collection.

![Library](https://i.imgur.com/rYaLZFe.png)

* **Search and Filter**: Users can search for games by name or Title ID and apply filters for specific categories or publishers.
* **Game Cards**: Each game is displayed with its icon, name, and publisher.
* **Local Status**: A badge on each game card clearly indicates if the title is `In shop` (available locally) or `Missing`.
* **Pagination**: The library is paginated to handle a large number of titles efficiently.

### 5. Game Details 
Provides a detailed view of a specific game selected from the library.

![Library](https://i.imgur.com/flJpNPN.png)

* **Game Info**: Displays the game's name, publisher, release date, number of players, file size, Title ID, and categories.
* **Description & Gallery**: Shows the official game description and a carousel of screenshots.
* **Related Content**: Lists all known Updates and DLCs for the base game, each with a status badge indicating if it is `In shop`.

### 6. File Watcher
![watcher](https://i.imgur.com/aNY35JO.png)

An interface to control the automated file system monitoring service.

* **Status and Control**: View the current status (`Running` or `Stopped`) and use buttons to start or stop the watcher service.
* **Manual Scan**: A "Scan All Now" button allows for manually triggering a full scan of all monitored directories.
* **Scan Progress**: When a scan is active, a progress bar shows the real-time status of the operation.
* **Monitored Directories**: Add new directories to watch or remove existing ones. The table lists each watched path and the last time it was scanned.

### 7. Settings
Allows configuration of the core server and shop.

![Library](https://i.imgur.com/S8VR7QO.png)

* **Shop Title**: Set the custom name for your shop that appears in the Tinfoil interface.
* **Core Network Settings**:
    * **Core Port**: Define the network port the Tinfoil server will listen on.
    * **Core Public URL (Domain)**: Optionally specify a public-facing domain or URL, which is useful when running the server behind a reverse proxy.
* **Restart on Save**: Any changes made on this page will automatically save the configuration and restart the core server to apply them.

### 8. Edit Shop Messages
A powerful tool to customize the text displayed within Tinfoil.

![Library](https://i.imgur.com/ffkX1mM.png)

* **Message Editor**: Provides a form with text areas for each configurable message key (e.g., `SHOP_MOTD_PLURAL`).
* **Dynamic Placeholders**: A documentation modal explains how to use placeholders like `{user}` and `{shop_title}` to insert dynamic information into the messages.
* **Special Fields**: The `BROWSER_FORBIDDEN` field supports HTML, allowing for a custom-formatted page to be shown to users who try to access the shop URL in a web browser.

### 9. Stored Logs (`stored_logs.html`)
An interface for viewing and searching the historical log database.

* **Advanced Filtering**: Allows for sophisticated searches of the entire log history.
* **Filter Criteria**: Logs can be filtered by:
    * Text within the message
    * Log Type (e.g., Login, Error, System)
    * Source (e.g., Core, Watcher, Admin)
    * User
    * Date Range (Start and End Date)
* **Detailed View**: For logs with extra data, a button allows expanding a detailed view of the raw JSON data associated with the event.
