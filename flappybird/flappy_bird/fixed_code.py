import pygame
import os
import random
import time
import neat
import visualize 
import pickle
pygame.font.init()


WIN_WIDTH = 575
WIN_HEIGHT = 800
FLOOR = 730

BIRD_IMGS = [pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "bird1.png"))), pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "bird2.png"))), pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "bird3.png"))) ]
PIPE_IMG = pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "pipe.png")))
BASE_IMG = pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "base.png")))
BG_IMG = pygame.transform.scale2x(pygame.image.load(os.path.join("C:\\Users\\Nick\\OneDrive\\Documents\\python_game\\flappy_bird\\imgs_b286d95d6d\\imgs", "bg.png")))

STAT_FONT = pygame.font.SysFont("comicsans", 50)

class Bird:
    IMGS = BIRD_IMGS
    MAX_ROTATION = 25
    ROT_VEL = 20
    ANIMATION_TIME = 5
    
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.tilt = 0
        self.tick_count = 0
        self.vel = 0
        self.height = self.y
        self.img_count = 0
        self.img = self.IMGS[0]
        
    def jump(self):
        self.vel = -15
        self.tick_count= 0 
        self.height = self.y
        
    def move(self):
        self.tick_count += 1
        
        d = self.vel*(self.tick_count) + 0.5 * (3) * (self.tick_count) ** 2
        
        if d >= 16:
            d = 16 
        if d < 0:
            d -= 2
        
        self.y = self.y + d 
        
        if d < 0 or self.y < self.height + 50:
            if self.tilt < self.MAX_ROTATION:
                self.tilt = self.MAX_ROTATION
        else:
            if self.tilt > -90:
                self.tilt -= self.ROT_VEL
                
        if self.vel < 16:
            self.vel += 1
                
    def draw(self, win):
        self.img_count += 1\
        
        if self.img_count < self.ANIMATION_TIME:
            self.img = self.IMGS[0]
        elif self.img_count < self.ANIMATION_TIME*2:
            self.img = self.IMGS[1]
        elif self.img_count < self.ANIMATION_TIME*3:
            self.img = self.IMGS[2]
        elif self.img_count < self.ANIMATION_TIME*4:
            self.img = self.IMGS[1]
        elif self.img_count < self.ANIMATION_TIME*4 + 1:
            self.img = self.IMGS[0]
            self.img_count = 0
        
        if self.tilt <= -80:
            self.img = self.IMGS[1]
            self.img_count = self.ANIMATION_TIME*2
        
        rotated_image = pygame.transform.rotate(self.img, self.tilt)
        new_rect = rotated_image.get_rect(center=self.img.get_rect(topleft = (self.x, self.y)).center)
        win.blit(rotated_image, new_rect.topleft)
    
    def get_mask(self):
        return pygame.mask.from_surface(self.img)
    
class Pipe:
    GAP = 200 
    VEL = 5
    
    def __init__(self, x):
        self.x = x
        self.height = 0
        
        
        self.top = 0
        self.bottom = 0
        self.PIPE_TOP = pygame.transform.flip(PIPE_IMG, False, True)
        self.PIPE_BOTTOM = PIPE_IMG
        
        self.passed = False
        self.set_height()
        
    def set_height(self):
        self.height = random.randrange(50, 450)
        self.top = self.height - self.PIPE_TOP.get_height()
        self.bottom = self.height + self.GAP
        
    def move(self):
        self.x -= self.VEL
        
    def draw(self, win):
        win.blit(self.PIPE_TOP, (self.x, self.top))
        win.blit(self.PIPE_BOTTOM, (self.x, self.bottom))
        
    def collide(self, bird):
        bird_mask = bird.get_mask()
        top_mask = pygame.mask.from_surface(self.PIPE_TOP)
        bottom_mask = pygame.mask.from_surface(self.PIPE_BOTTOM)
        
        top_offset = (self.x - bird.x, self.top - round(bird.y))
        bottom_offset = (self.x - bird.x, self.bottom - round(bird.y))
        
        b_point = bird_mask.overlap(bottom_mask, bottom_offset)
        t_point = bird_mask.overlap(top_mask, top_offset)
        
        if t_point or b_point:
            return True
        
        return False
    
class Base:
    VEL = 4
    WIDTH = BASE_IMG.get_width()
    IMG = BASE_IMG
    
    def __init__(self, y):
        self.y = y
        self.x1 = 0
        self.x2 = self.WIDTH
        
    def move(self):
        self.x1 -= self.VEL
        self.x2 -= self.VEL
        
        if self.x1 + self.WIDTH < 0:
            self.x1 = self.x2 + self.WIDTH
            
            if self.x2 + self.WIDTH < 0:
                self.x2 = self.x1 + self.WIDTH
        
    def draw(self, win):
        win.blit(self.IMG, (self.x1, self.y))
        win.blit(self.IMG, (self.x2, self.y))

def draw_window(win, bird, pipes, base, score):
    win.blit(BG_IMG, (0,0))
    
    for pipe in pipes:
        pipe.draw(win)
        
    text = STAT_FONT.render("Score:" + str(score), 1,(255,255,255))
    win.blit(text, (WIN_WIDTH - 10 - text.get_width(), 10))
        
    base.draw(win)
    bird.draw(win)
    
    pygame.display.update()

def main(genomes, config):
    nets = []
    ge = []
    birds = []
    
    for g in genomes:
        net = neat.nn.FeedForwardNetwork(g, config)
        nets.append(net)
        birds.append(Bird(230, 350))
        g.fitness == 0
        ge.append(g)
                     


    birds = Bird(230,350)
    base = Base(730)
    pipes = [Pipe(700)]
    win = pygame.display.set_mode((WIN_WIDTH, WIN_HEIGHT))
    clock = pygame.time.Clock()
    
    score = 0
    
    run = True
    while run:
        clock.tick(30)
        
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                run = False
                
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_SPACE:
                    bird.jump()
                
        bird.move() 
        add_pipe  = False
        rem = []
        for pipe in pipes:
            for x, bird in enumerate(birds):
                if pipe.collide(bird):
                  ge[x].fitness -= 1  
                  birds.pop(x)
                  nets.pop(x)
                  ge.pop(x)
            
                if not pipe.passed and pipe.x < birds.x:
                        pipe.passed = True
                        add_pipe =True
            if pipe.x + pipe.PIPE_TOP.get_width() < 0:
                rem.append(pipe)
            
                
                    
            pipe.move()
            
        if add_pipe:
            score += 1
            for g in ge:
                g, fitness += 5
            pipes.append(Pipe(600))
            
            for r in rem:
                pipes.remove(r)
                
            for x,bird in enumerate(birds):   
                if bird.y + bird.img.get_height() >= 730:
                    birds.pop(x)
                    nets.pop(x)
                    ge.pop(x)
                
        base.move()    
        draw_window(win, bird, pipes, base, score) 
                  
    pygame.quit()
    quit()
    
main()

def run(config_path):
    config = neat.config.Config(neat.DefaultGenome, neat.DefaultReproduction,
                                neat.DefaultSpeciesSet, neat.DefaultStagnation,
                                config_path)
    
    p = neat.Population(config)
    
    p.addd_reporter(neat.StdOutReporter(True))
    stats = neat.StatisticsReporter()
    p.add_reporter(stats)
    
    winner = p.run(main,50)


if __name__ == "__main__":
    local_directory = os.path.dirname(__file__)
    config_path = os.path.join(local_directory, "config-feedforward.txt")
    run(config_path)