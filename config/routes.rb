Rails.application.routes.draw do
 root 'pages#index'
 resources :questions do 
   resources :answers, except: %i[new show]
 end
end
