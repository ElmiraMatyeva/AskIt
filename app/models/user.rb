class User < ApplicationRecord
  attr_accessor :old_password
    # чтобы создать виртуальный атрибут для юзера (он не будет попадать в базу данных, а будет сущ-ть просто на объекте User), 
    # с его помощью мы будем отрисовывать поле для ввода старого пароля
  
    # отменяем валидации от гема bcrypt, чтобы прописать необходимые 
    # валидации самостоятельно  
  has_secure_password validations: false
  validate  :password_presence
  validate  :password_complexity

    # лямбда здесь означает, что эту валидацию надо запускать, только если 
    # юзер ввел новый пароль. Если новый пароль не был указан (т.е. юзер меняет 
    # другие поля, а пароль менять не хочет), то валидацию игнорируем
  validate  :correct_old_password, on: :update, if: -> { password.present? }

  validates :password, confirmation: true, allow_blank: true
    # allow_blank: true означает, что при обновлении профиля юзер может не захотеть 
    # вводить пароль снова (то есть, мы разрешаем оставить поле пароля пустым)

  validates :name, presence: true
  validates :email, presence: true, uniqueness: true, 'valid_email2/email': true
  
  private 

  def password_complexity
    # Regexp extracted from https://stackoverflow.com/questions/19605150/regex-for-password-must-contain-at-least-eight-characters-at-least-one-number-a
    return if password.blank? || password =~ /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,70}$/

    errors.add :password, 'complexity requirement not met. Length should be 8-70 characters and include: 1 uppercase, 1 lowercase, 1 digit and 1 special character'
  end

  def password_presence
    # нужно добавить для пароля warning, что он пустой, но только не в том случае, 
    # если password_digest уже был указан. То есть, password_digest.present? 
    # означает, что Юзер уже указал пароль раньше. Значит, при обновлении профиля 
    # он может указать пароль, а может и оставить поле пустым.
    errors.add(:password, :blank) unless password_digest.present?
  end

  def correct_old_password
    # password_digest_was спец.метод RoR, означает, что надо вытащить именно старый 
    # пароль, который в бд хранится, а не новый, который хранится в памяти. 
    # is_password?(old_password) значит мы сделаем digest на основе старого пароля
    # и сравним с digest, который хранится в бд
    return if BCrypt::Password.new(password_digest_was).is_password?(old_password)

    errors.add :old_password, 'is incorrect'
  end
end
