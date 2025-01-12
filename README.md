## Description

This backend is a Flask-based web application that provides user authentication and profile management functionalities. It is designed to handle user sign-up, login, profile updates, and account management. The backend interacts with a MySQL database using SQLAlchemy for ORM (Object-Relational Mapping).
This backend leverages a combination of Flask, SQLAlchemy, PyJWT, MySQL, and Werkzeug to provide a robust and secure user authentication and profile management system. Flask serves as the web framework, SQLAlchemy handles database interactions, PyJWT manages token-based authentication, MySQL stores user data, and Werkzeug provides essential utilities for web application development. This technology stack ensures efficient and secure handling of user data and authentication processes.


## PyJWT Usage in This Backend

#### How PyJWT is Used in This Backend:

1. Token Generation:
When a user logs in, a JWT is generated using the create_access_token function. This token includes the user's ID and an expiration time. The token is then sent in the database, to the client we give a code related to the token, which stores it and includes it in the Authorization header of subsequent requests.

| id 	| session_string 	| jwt                                                   	|
|----	|----------------	|-------------------------------------------------------	|
| 44 	| 8PBV22S        	| eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6Z... 	|

As can be seen, nothing relate to the id of the user, the id is inside of jwt and need special decode for extract the ID.

2. Token Verification:
For protected routes, the backend verifies the JWT included in the Authorization header of incoming requests. The token is decoded using the jwt.decode function, which extracts the user's ID and other claims. If the token is valid, the request is processed; otherwise, an error response is returned.

3. Session Management:
The backend uses JWTs to manage user sessions. When a user logs in, a session is created with the generated token. This session is used to authenticate the user for subsequent requests.

## Key Features: 
### User Authentication:

Sign-Up: Allows users to create an account by providing an email and password. This is keeped it simple.

```python
@main.route('/creare-cont' , methods=['POST'])
def insert_data():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    firstName = data.get('firstName')
    lastName = data.get('lastName')
    userName = data.get('username')

    try: 
        has = HashPass.passwordHash(password) 
        new_user = User( userName, email, lastName, firstName , has)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': "The user account is create with succes"}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
```
### User Authentication:

About HashPass.passwordHash(password) is a special medotdh I create to hash the password, validate email format and checking for missing fields are done in the FrontEnd, checking for existing email and username 
I have a separated function that is used in FrontEnd when input is out of focus, the function is call via API. 

Login: Users can log in using their email and password. A JWT (JSON Web Token) is generated for authenticated sessions. Dummy profile and social link data are created for new users.

```python
        if user:
            access_token = create_access_token(identity=check_user.id, expires_delta=datetime.timedelta(days=1))    
            insert_session = Session(add_session_string, access_token)
            dummy_profile = ProfileCard(
                occupation="May I ask you what do you do?",
                homeaddress="How far are you ?",
                country="I guess you are from Nice ?",
                county="France ?",
                user_id=check_user.id,
                image=b""  
            )
            dummy_social_links = SocialLinks(
                linkedin="https://linkedin.com/",
                facebook="https://facebook.com/",
                github="https://github.com/",
                instagram="https://instagram.com/",
                twitter="https://twitter.com/",
                youtube="https://youtube.com/",
                description="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
                user_id=check_user.id
            )            

            db.session.add(insert_session)
            db.session.commit()

            db.session.add(dummy_profile)
            db.session.commit()

            db.session.add(dummy_social_links)
            db.session.commit()
            return jsonify({'message': add_session_string}), 200
        else:   
            return jsonify({'message': 'Password or user are incorrect'}), 202
```

### Profile Management:

Set Contact Details: Allows users to update their contact details, including occupation, home address, country, county, and profile image.


Set Social Links: Allows users to update their social links, such as LinkedIn, Facebook, GitHub, Instagram, Twitter, and YouTube.

```python
# Retrieve the existing social links
            social_links = SocialLinks.query.filter_by(user_id=user_id).first()

            if social_links:
                # Update the existing social links with new data
                social_links.linkedin = data.get("linkedIn", social_links.linkedin)
                social_links.facebook = data.get("faceBook", social_links.facebook)                
                social_links.github = data.get("gitHub", social_links.github)            
                social_links.instagram = data.get("instagram", social_links.instagram)            
                social_links.twitter = data.get("twitter", social_links.twitter)                
                social_links.youtube = data.get("youtube", social_links.youtube)
                social_links.description = data.get("description", social_links.description)
```
I use this approach because this is an update.


Get Profile: Retrieves the user's profile information, including occupation, home address, country, county, and social links.

```python
    try:
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["xxxxx"])
        user_id = decoded_token.get('sub')  # Extract user ID from 'sub' key
    except jwt.DecodeError as e:
        return jsonify({'error': 'Invalid token format', 'message': str(e)}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401



        `````````````````````````````````````````````````````````````````````````````````````

         profile = ProfileCard.query.filter_by(user_id=user_id).first()
    social_links = SocialLinks.query.filter_by(user_id=user_id).first()
    user = User.query.filter_by(id=user_id).first()
    if not profile:
        return jsonify({'error': 'Profile or user not found'}), 404
    image_base64 = base64.b64encode(profile.image).decode('utf-8')
    return jsonify({
        'HomeAddress': profile.homeaddress,
        'Country': profile.country,
        'County': profile.county,
        'Occupation': profile.occupation,
        'Image': image_base64,  # Assuming image is stored as binary data
        'FullName': ' '.join([user.first_name, user.last_name]),
        'Email': user.email,
        'LinkedIn': social_links.linkedin,
        'FaceBook': social_links.facebook,
        'GitHub': social_links.github,
        'Instagram': social_links.instagram,
        'Twitter': social_links.twitter,
        'Youtube': social_links.youtube,
        'Description': social_links.description

    }), 200
```

### Account Management:

Everything start with chinkd the jwt:

```python
ses = Session.query.filter_by(session_string=token).first()
decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["#####"])
```

Change Password: Allows users to change their password by providing the current password and a new password.
```python
 # Verify the current password
        if not HashPass.check_password(user.password, current_password):
            return jsonify({'message': 'Current password is incorrect'}), 400

        # Update the password
        user.password = HashPass.passwordHash(new_password)
        db.session.commit()
```

Change Email: Allows users to update their email address.
```python
 user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Update the email
        user.email = new_email
        db.session.commit()
```
Change Username: Allows users to update their username, ensuring the new username is not already taken.
```python
existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            return jsonify({'message': 'Username already taken'}), 400

        # Update the username
        user.username = new_username
        db.session.commit()
```

Delete Account: Allows users to delete their account and all related data, including profile and social links.
```python
ser = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Delete related records
        ProfileCard.query.filter_by(user_id=user_id).delete()
        SocialLinks.query.filter_by(user_id=user_id).delete()

        # Delete the user record
        db.session.delete(user)
        db.session.commit()
```

Technologies Used:
Flask: A lightweight WSGI web application framework in Python.
SQLAlchemy: An ORM library for managing database interactions.
PyJWT: A Python library for working with JSON Web Tokens.
MySQL: A relational database management system for storing user data.
Werkzeug: A comprehensive WSGI web application library used for password hashing and security.

Example Endpoints:
1.  POST /intra-in-cont: Sign up a new user.
2.  POST /login: Log in an existing user.
3.  GET /getProfile: Retrieve the user's profile information.
4.  POST /setContactDetail: Update the user's contact details.
6.  POST /setSocialLink: Update the user's social links.
7.  POST /changePassword: Change the user's password.
8.  POST /changeEmail: Change the user's email address.
9.  POST /changeUsername: Change the user's username.
10. DELETE /deleteAccount: Delete the user's account and all related data.

This backend provides a robust foundation for user authentication and profile management, ensuring secure and efficient handling of user data.

This description provides a comprehensive overview of the backend's functionality, key features, and technologies used. Adjust the details as needed to match your specific implementation.

