









if __name__ == '__main__':
    fenetre = view.View()
    isconnected = fenetre.MenuScreen()
    if isconnected:
        g=Game()
        g.run() 
