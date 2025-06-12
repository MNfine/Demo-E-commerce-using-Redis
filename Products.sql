CREATE DATABASE Products;
Use Products;
CREATE TABLE Products (
    product_id INT PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    price INT NOT NULL,
	image_path NVARCHAR(255) NOT NULL,
    stock INT NOT NULL
);
CREATE TABLE Cart (
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    PRIMARY KEY (user_id, product_id)
);
CREATE TABLE Cart_Items (
    cart_item_id INT PRIMARY KEY IDENTITY(1,1),
    cart_id INT FOREIGN KEY REFERENCES Carts(cart_id) ON DELETE CASCADE,
    product_id INT FOREIGN KEY REFERENCES Products(product_id),
    quantity INT NOT NULL CHECK (quantity > 0)
);

CREATE TABLE Users (
    user_id INT IDENTITY(1,1) PRIMARY KEY,
    username NVARCHAR(100),
    password NVARCHAR(255),
    email NVARCHAR(255),
    phone NVARCHAR(20)
);

INSERT INTO Users (user_id, username, password_hash) 
VALUES ('1', 'mnfine', 'mnfine');

INSERT INTO Products (product_id, name, price, image_path, stock) VALUES
(1, 'EBIKE GIANT TALON E+ 3 29ER', 2899, 'static/images/2022_Talon3-29er_Blue-Ashes.jpg', 10),
(2, 'EBIKE AVENTON ABOUND', 3333, 'static/images/01_Abound-AG_Sage_Side_e80dc9ac-740f-4eca-a7c9-1313c9bf0040.jpg', 5),
(3, 'EBIKE PACE 500.3', 3040, 'static/images/pace--500-camo-traditional-01.jpg', 7),
(4, 'VF DRGNFLY', 745, 'static\images\dragonFly.png', 4),
(5, 'EBIKE AVENTON AVENTURE.2', 2899, 'static\images\Aventure2-traditional-slate-01.jpg', 2),
(6, 'EBIKE-MTB AVENTON RAMBLAS EMTB', 3016, 'static\images\ramblas-gallery-borealis-01.avif', 4),
(7, 'VELORRETI ELECTRIC ACE-TWO', 3790, 'static\images\Ace_Two_Matte_Black_NEW.jpg', 3),
(8, 'VELORRETI ELECTRIC IVY-TWO', 3790, 'static\images\Ivy_Two_Matte_Black_NEW.jpg', 6);

Drop table Users 
Drop table Products 
