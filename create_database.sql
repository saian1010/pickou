create database pickou;
Drop table users;
Drop table posts;
Drop table votes;
Drop table vote_options;
Drop table user_votes;
Drop table comments;
Drop table likes;

-- users
CREATE TABLE users (
                       user_id BIGINT NOT NULL AUTO_INCREMENT,
                       username VARCHAR(20) NOT NULL Default '',
                       password_hash CHAR(60) BINARY NOT NULL,
                       email VARCHAR(320) NOT NULL Default '',
                       phone VARCHAR(50) NOT NULL Default '',
                       dob_year int(10) NOT NULL Default 0,
                       dob_month int(10) NOT NULL Default 0,
                       first_name VARCHAR(50) NOT NULL Default 'N/A',
                       last_name VARCHAR(50) NOT NULL Default 'N/A',
                       nick_name VARCHAR(50) NOT NULL Default 'N/A',
                       gender int(2) NOT NULL Default 0 comment '性别，0未知，1男，2女，3无性别',
                       nationality VARCHAR(20) NOT NULL Default '' comment '国籍',
                       profile_image VARCHAR(255) NOT NULL Default '',
                       role ENUM('visitor', 'helper', 'admin') NOT NULL Default 'visitor' comment '默认visitor',
                       authenticate int(2) NOT NULL Default 0 comment '0未认证，1已认证',
                       status ENUM('active', 'inactive') NOT NULL Default 'active',
                       created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                       PRIMARY KEY (user_id)
);

-- issues
CREATE TABLE posts (
                       post_id BIGINT NOT NULL AUTO_INCREMENT,
                       user_id BIGINT NOT NULL,
                       vote_id BIGINT NOT NULL,
                       title VARCHAR(255) NOT NULL,
                       content TEXT NOT NULL,
                       created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                       PRIMARY KEY (post_id)
);

CREATE TABLE votes(
                      vote_id BIGINT NOT NULL AUTO_INCREMENT,
                      title VARCHAR(50) NOT NULL Default '',
                      vote_type int(2) NOT NULL Default 1 comment '1单选，2多选',
                      created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                      updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                      PRIMARY KEY (vote_id)
);

CREATE TABLE vote_options(
                             vote_option_id BIGINT NOT NULL AUTO_INCREMENT,
                             vote_id BIGINT NOT NULL,
                             title VARCHAR(50) NOT NULL Default '',
                             created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                             updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                             PRIMARY KEY (vote_option_id)
);

-- 用户投票记录表
CREATE TABLE user_votes(
                           user_vote_id BIGINT NOT NULL AUTO_INCREMENT,
                           user_id BIGINT NOT NULL comment '用户id',
                           post_id BIGINT NOT NULL comment '用户id',
                           vote_id BIGINT NOT NULL comment '投票id',
                           vote_option_id BIGINT NOT NULL comment '投票选项id',
                           created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                           updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                           PRIMARY KEY (user_vote_id)
);

-- comments
CREATE TABLE comments (
                          comment_id BIGINT NOT NULL AUTO_INCREMENT,
                          post_id BIGINT NOT NULL,
                          user_id BIGINT NOT NULL,
                          content TEXT NOT NULL,
                          created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          PRIMARY KEY (comment_id)
);

-- likes
CREATE TABLE likes (
                          like_id BIGINT NOT NULL AUTO_INCREMENT,
                          post_id BIGINT NOT NULL,
                          user_id BIGINT NOT NULL,
                          created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          PRIMARY KEY (like_id)
);


-- likes
CREATE TABLE follows (
                          follow_id BIGINT NOT NULL AUTO_INCREMENT,
                          user_id BIGINT NOT NULL,
                          follower_id BIGINT NOT NULL,
                          created_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          updated_at TIMESTAMP NOT NULL Default CURRENT_TIMESTAMP,
                          PRIMARY KEY (follow_id)
);

CREATE TABLE `post_images` (
  `image_id` int(11) NOT NULL AUTO_INCREMENT,
  `post_id` int(11) NOT NULL,
  `image_path` varchar(255) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`image_id`),
  KEY `post_id` (`post_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;