USE [AdventureWorks2012]
GO

CREATE TABLE ExternalLoginDetails(
	Pass varchar(max),
	Vi varchar(max),
	Keyy varchar(max))
GO

ALTER TABLE ExternalLoginDetails
    ADD EncryptedKey varbinary(128),EncryptedVi varbinary(128); 
GO

CREATE CERTIFICATE Rijndael
   WITH SUBJECT = 'Rijndael cert';
GO

CREATE SYMMETRIC KEY SSN_Key_01
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE Rijndael;
GO

CREATE PROCEDURE dbo.ExtrenalReturnLoginDetails
AS
BEGIN
	SELECT Pass from ExternalLoginDetails
END
GO


CREATE PROCEDURE dbo.InsertUpdateLoginDetails
@Pass varbinary(MAX)
AS
BEGIN
	IF exists (SELECT * FROM ExternalLoginDetails)
		BEGIN
		
			UPDATE ExternalLoginDetails set Pass=@Pass 
		END
	ELSE
		BEGIN
			INSERT INTO ExternalLoginDetails (Pass) VALUES (@Pass)
		END
END
GO

	



